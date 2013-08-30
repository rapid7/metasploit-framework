# -*- coding: binary -*-
require 'msf/core'
require 'msf/base'
require 'msf/ui'
require 'msf/ui/console/framework_event_manager'
require 'msf/ui/console/command_dispatcher'
require 'msf/ui/console/table'
require 'find'
require 'erb'
require 'rexml/document'
require 'fileutils'
require 'digest/md5'

module Msf
module Ui
module Console

###
#
# This class implements a user interface driver on a console interface.
#
###

class Driver < Msf::Ui::Driver

	ConfigCore  = "framework/core"
	ConfigGroup = "framework/ui/console"

	DefaultPrompt     = "%undmsf%clr"
	DefaultPromptChar = "%clr>"

	#
	# The console driver processes various framework notified events.
	#
	include FrameworkEventManager

	#
	# The console driver is a command shell.
	#
	include Rex::Ui::Text::DispatcherShell

	#
	# Initializes a console driver instance with the supplied prompt string and
	# prompt character.  The optional hash can take extra values that will
	# serve to initialize the console driver.
	#
	# The optional hash values can include:
	#
	# AllowCommandPassthru
	#
	# 	Whether or not unknown commands should be passed through and executed by
	# 	the local system.
	#
	# RealReadline
	#
	# 	Whether or to use the system Readline or the RBReadline (default)
	#
	# HistFile
	#
	#	Name of a file to store command history
	#
	def initialize(prompt = DefaultPrompt, prompt_char = DefaultPromptChar, opts = {})

		# Choose a readline library before calling the parent
		rl = false
		rl_err = nil
		begin
			if(opts['RealReadline'])
				require 'readline'
				rl = true
			end
		rescue ::LoadError
			rl_err = $!
		end

		# Default to the RbReadline wrapper
		require 'readline_compatible' if(not rl)

		histfile = opts['HistFile'] || Msf::Config.history_file

		# Initialize attributes
		self.framework = opts['Framework'] || Msf::Simple::Framework.create(opts)

		if self.framework.datastore['Prompt']
			prompt = self.framework.datastore['Prompt']
			prompt_char = self.framework.datastore['PromptChar'] || DefaultPromptChar
		end

		# Call the parent
		super(prompt, prompt_char, histfile, framework)

		# Temporarily disable output
		self.disable_output = true

		# Load pre-configuration
		load_preconfig

		# Initialize the user interface to use a different input and output
		# handle if one is supplied
		input = opts['LocalInput']
		input ||= Rex::Ui::Text::Input::Stdio.new

		if (opts['LocalOutput'])
			if (opts['LocalOutput'].kind_of?(String))
				output = Rex::Ui::Text::Output::File.new(opts['LocalOutput'])
			else
				output = opts['LocalOutput']
			end
		else
			output = Rex::Ui::Text::Output::Stdio.new
		end

		init_ui(input, output)
		init_tab_complete

		# Add the core command dispatcher as the root of the dispatcher
		# stack
		enstack_dispatcher(CommandDispatcher::Core)

		# Report readline error if there was one..
		if not rl_err.nil?
			print_error("***")
			print_error("* WARNING: Unable to load readline: #{rl_err}")
			print_error("* Falling back to RbReadLine")
			print_error("***")
		end


		# Add the database dispatcher if it is usable
		if (framework.db.usable)
			require 'msf/ui/console/command_dispatcher/db'
			enstack_dispatcher(CommandDispatcher::Db)
		else
			print_error("***")
			if framework.db.error == "disabled"
				print_error("* WARNING: Database support has been disabled")
			else
				print_error("* WARNING: No database support: #{framework.db.error.class} #{framework.db.error}")
			end
			print_error("***")
		end

		begin
			require 'openssl'
		rescue ::LoadError
			print_error("***")
			print_error("* WARNING: No OpenSSL support. This is required by meterpreter payloads and many exploits")
			print_error("* Please install the ruby-openssl package (apt-get install libopenssl-ruby on Debian/Ubuntu")
			print_error("***")
		end

		# Register event handlers
		register_event_handlers

		# Re-enable output
		self.disable_output = false

		# Whether or not command passthru should be allowed
		self.command_passthru = (opts['AllowCommandPassthru'] == false) ? false : true

		# Disables "dangerous" functionality of the console
		@defanged = opts['Defanged'] == true

		# If we're defanged, then command passthru should be disabled
		if @defanged
			self.command_passthru = false
		end

		# Parse any specified database.yml file
		if framework.db.usable and not opts['SkipDatabaseInit']

			# Append any migration paths necessary to bring the database online
			if opts['DatabaseMigrationPaths']
				opts['DatabaseMigrationPaths'].each do |migrations_path|
					ActiveRecord::Migrator.migrations_paths << migrations_path
				end
			end

			# Look for our database configuration in the following places, in order:
			#	command line arguments
			#	environment variable
			#	configuration directory (usually ~/.msf3)
			dbfile = opts['DatabaseYAML']
			dbfile ||= ENV["MSF_DATABASE_CONFIG"]
			dbfile ||= File.join(Msf::Config.get_config_root, "database.yml")
			if (dbfile and File.exists? dbfile)
				if File.readable?(dbfile)
					dbinfo = YAML.load(File.read(dbfile))
					dbenv  = opts['DatabaseEnv'] || "production"
					db     = dbinfo[dbenv]
				else
					print_error("Warning, #{dbfile} is not readable. Try running as root or chmod.")
				end
				if not db
					print_error("No database definition for environment #{dbenv}")
				else
					if not framework.db.connect(db)
						if framework.db.error.to_s =~ /RubyGem version.*pg.*0\.11/i
							print_error("***")
							print_error("*")
							print_error("* Metasploit now requires version 0.11 or higher of the 'pg' gem for database support")
							print_error("* There a three ways to accomplish this upgrade:")
							print_error("* 1. If you run Metasploit with your system ruby, simply upgrade the gem:")
							print_error("*    $ rvmsudo gem install pg ")
							print_error("* 2. Use the Community Edition web interface to apply a Software Update")
							print_error("* 3. Uninstall, download the latest version, and reinstall Metasploit")
							print_error("*")
							print_error("***")
							print_error("")
							print_error("")
						end

						print_error("Failed to connect to the database: #{framework.db.error}")
					else
						self.framework.modules.refresh_cache_from_database

						if self.framework.modules.cache_empty?
							print_status("The initial module cache will be built in the background, this can take 2-5 minutes...")
						end
					end
				end
			end
		end

		# Initialize the module paths only if we didn't get passed a Framework instance
		unless opts['Framework']
			# Configure the framework module paths
			self.framework.init_module_paths
			self.framework.modules.add_path(opts['ModulePath']) if opts['ModulePath']

			# Rebuild the module cache in a background thread
			self.framework.threads.spawn("ModuleCacheRebuild", true) do
				self.framework.modules.refresh_cache_from_module_files
			end
		end

		# Load console-specific configuration (after module paths are added)
		load_config(opts['Config'])

		# Process things before we actually display the prompt and get rocking
		on_startup(opts)

		# Process the resource script
		if opts['Resource'] and opts['Resource'].kind_of? Array
			opts['Resource'].each { |r|
				load_resource(r)
			}
		else
			# If the opt is nil here, we load ~/.msf3/msfconsole.rc
			load_resource(opts['Resource'])
		end

		# Process any additional startup commands
		if opts['XCommands'] and opts['XCommands'].kind_of? Array
			opts['XCommands'].each { |c|
				run_single(c)
			}
		end
	end

	#
	# Configure a default output path for jUnit XML output
	#
	def junit_setup(output_path)
		output_path = ::File.expand_path(output_path)

		::FileUtils.mkdir_p(output_path)
		@junit_output_path = output_path
		@junit_error_count = 0
		print_status("Test Output: #{output_path}")

		# We need at least one test success in order to pass
		junit_pass("framework_loaded")
	end

	#
	# Emit a new jUnit XML output file representing an error
	#
	def junit_error(tname, ftype, data = nil)

		if not @junit_output_path
			raise RuntimeError, "No output path, call junit_setup() first"
		end

		data ||= framework.inspect.to_s

		e = REXML::Element.new("testsuite")

		c = REXML::Element.new("testcase")
		c.attributes["classname"] = "msfrc"
		c.attributes["name"]  = tname

		f = REXML::Element.new("failure")
		f.attributes["type"] = ftype

		f.text = data
		c << f
		e << c

		bname = ("msfrpc_#{tname}").gsub(/[^A-Za-z0-9\.\_]/, '')
		bname << "_" + Digest::MD5.hexdigest(tname)

		fname = ::File.join(@junit_output_path, "#{bname}.xml")
		cnt   = 0
		while ::File.exists?( fname )
			cnt  += 1
			fname = ::File.join(@junit_output_path, "#{bname}_#{cnt}.xml")
		end

		::File.open(fname, "w") do |fd|
			fd.write(e.to_s)
		end

		print_error("Test Error: #{tname} - #{ftype} - #{data}")
	end

	#
	# Emit a new jUnit XML output file representing a success
	#
	def junit_pass(tname)

		if not @junit_output_path
			raise RuntimeError, "No output path, call junit_setup() first"
		end

		# Generate the structure of a test case run
		e = REXML::Element.new("testsuite")
		c = REXML::Element.new("testcase")
		c.attributes["classname"] = "msfrc"
		c.attributes["name"]  = tname
		e << c

		# Generate a unique name
		bname = ("msfrpc_#{tname}").gsub(/[^A-Za-z0-9\.\_]/, '')
		bname << "_" + Digest::MD5.hexdigest(tname)

		# Generate the output path, allow multiple test with the same name
		fname = ::File.join(@junit_output_path, "#{bname}.xml")
		cnt   = 0
		while ::File.exists?( fname )
			cnt  += 1
			fname = ::File.join(@junit_output_path, "#{bname}_#{cnt}.xml")
		end

		# Write to our test output location, as specified with junit_setup
		::File.open(fname, "w") do |fd|
			fd.write(e.to_s)
		end

		print_good("Test Pass: #{tname}")
	end


	#
	# Emit a jUnit XML output file and throw a fatal exception
	#
	def junit_fatal_error(tname, ftype, data)
		junit_error(tname, ftype, data)
		print_error("Exiting")
		run_single("exit -y")
	end

	#
	# Loads configuration that needs to be analyzed before the framework
	# instance is created.
	#
	def load_preconfig
		begin
			conf = Msf::Config.load
		rescue
			wlog("Failed to load configuration: #{$!}")
			return
		end

		if (conf.group?(ConfigCore))
			conf[ConfigCore].each_pair { |k, v|
				on_variable_set(true, k, v)
			}
		end
	end

	#
	# Loads configuration for the console.
	#
	def load_config(path=nil)
		begin
			conf = Msf::Config.load(path)
		rescue
			wlog("Failed to load configuration: #{$!}")
			return
		end

		# If we have configuration, process it
		if (conf.group?(ConfigGroup))
			conf[ConfigGroup].each_pair { |k, v|
				case k.downcase
					when "activemodule"
						run_single("use #{v}")
				end
			}
		end
	end

	#
	# Saves configuration for the console.
	#
	def save_config
		# Build out the console config group
		group = {}

		if (active_module)
			group['ActiveModule'] = active_module.fullname
		end

		# Save it
		begin
			Msf::Config.save(ConfigGroup => group)
		rescue ::Exception
			print_error("Failed to save console config: #{$!}")
		end
	end

	#
	# Processes the resource script file for the console.
	#
	def load_resource(path=nil)
		path ||= File.join(Msf::Config.config_directory, 'msfconsole.rc')
		return if not ::File.readable?(path)
		resource_file = ::File.read(path)

		self.active_resource = resource_file

		# Process ERB directives first
		print_status "Processing #{path} for ERB directives."
		erb = ERB.new(resource_file)
		processed_resource = erb.result(binding)

		lines = processed_resource.each_line.to_a
		bindings = {}
		while lines.length > 0

			line = lines.shift
			break if not line
			line.strip!
			next if line.length == 0
			next if line =~ /^#/

			# Pretty soon, this is going to need an XML parser :)
			# TODO: case matters for the tag and for binding names
			if line =~ /<ruby/
				if line =~ /\s+binding=(?:'(\w+)'|"(\w+)")(>|\s+)/
					bin = ($~[1] || $~[2])
					bindings[bin] = binding unless bindings.has_key? bin
					bin = bindings[bin]
				else
					bin = binding
				end
				buff = ''
				while lines.length > 0
					line = lines.shift
					break if not line
					break if line =~ /<\/ruby>/
					buff << line
				end
				if ! buff.empty?
					print_status("resource (#{path})> Ruby Code (#{buff.length} bytes)")
					begin
						eval(buff, bin)
					rescue ::Interrupt
						raise $!
					rescue ::Exception => e
						print_error("resource (#{path})> Ruby Error: #{e.class} #{e} #{e.backtrace}")
					end
				end
			else
				print_line("resource (#{path})> #{line}")
				run_single(line)
			end
		end

		self.active_resource = nil
	end

	#
	# Saves the recent history to the specified file
	#
	def save_recent_history(path)
		num = Readline::HISTORY.length - hist_last_saved - 1

		tmprc = ""
		num.times { |x|
			tmprc << Readline::HISTORY[hist_last_saved + x] + "\n"
		}

		if tmprc.length > 0
			print_status("Saving last #{num} commands to #{path} ...")
			save_resource(tmprc, path)
		else
			print_error("No commands to save!")
		end

		# Always update this, even if we didn't save anything. We do this
		# so that we don't end up saving the "makerc" command itself.
		self.hist_last_saved = Readline::HISTORY.length
	end

	#
	# Creates the resource script file for the console.
	#
	def save_resource(data, path=nil)
		path ||= File.join(Msf::Config.config_directory, 'msfconsole.rc')

		begin
			rcfd = File.open(path, 'w')
			rcfd.write(data)
			rcfd.close
		rescue ::Exception
		end
	end

	#
	# Called before things actually get rolling such that banners can be
	# displayed, scripts can be processed, and other fun can be had.
	#
	def on_startup(opts = {})
		# Check for modules that failed to load
		if framework.modules.module_load_error_by_path.length > 0
			print_error("WARNING! The following modules could not be loaded!")

			framework.modules.module_load_error_by_path.each do |path, error|
				print_error("\t#{path}: #{error}")
			end
		end

		framework.events.on_ui_start(Msf::Framework::Revision)

		run_single("banner") unless opts['DisableBanner']

		opts["Plugins"].each do |plug|
			run_single("load '#{plug}'")
		end if opts["Plugins"]

		self.on_command_proc = Proc.new { |command| framework.events.on_ui_command(command) }
	end

	#
	# Called when a variable is set to a specific value.  This allows the
	# console to do extra processing, such as enabling logging or doing
	# some other kind of task.  If this routine returns false it will indicate
	# that the variable is not being set to a valid value.
	#
	def on_variable_set(glob, var, val)
		case var.downcase
			when "payload"

				if (framework and framework.payloads.valid?(val) == false)
					return false
				elsif (active_module)
					active_module.datastore.clear_non_user_defined
				elsif (framework)
					framework.datastore.clear_non_user_defined
				end
			when "sessionlogging"
				handle_session_logging(val) if (glob)
			when "consolelogging"
				handle_console_logging(val) if (glob)
			when "loglevel"
				handle_loglevel(val) if (glob)
			when "prompt"
				update_prompt(val, framework.datastore['PromptChar'] || DefaultPromptChar, true)
			when "promptchar"
				update_prompt(framework.datastore['Prompt'], val, true)
		end
	end

	#
	# Called when a variable is unset.  If this routine returns false it is an
	# indication that the variable should not be allowed to be unset.
	#
	def on_variable_unset(glob, var)
		case var.downcase
			when "sessionlogging"
				handle_session_logging('0') if (glob)
			when "consolelogging"
				handle_console_logging('0') if (glob)
			when "loglevel"
				handle_loglevel(nil) if (glob)
		end
	end

	#
	# The framework instance associated with this driver.
	#
	attr_reader   :framework
	#
	# Whether or not commands can be passed through.
	#
	attr_reader   :command_passthru
	#
	# The active module associated with the driver.
	#
	attr_accessor :active_module
	#
	# The active session associated with the driver.
	#
	attr_accessor :active_session
	#
	# The active resource file being processed by the driver
	#
	attr_accessor :active_resource

	#
	# If defanged is true, dangerous functionality, such as exploitation, irb,
	# and command shell passthru is disabled.  In this case, an exception is
	# raised.
	#
	def defanged?
		if @defanged
			raise DefangedException
		end
	end

	def stop
		framework.events.on_ui_stop()
		super
	end

protected

	attr_writer   :framework # :nodoc:
	attr_writer   :command_passthru # :nodoc:

	#
	# If an unknown command was passed, try to see if it's a valid local
	# executable.  This is only allowed if command passthru has been permitted
	#
	def unknown_command(method, line)

		[method, method+".exe"].each do |cmd|
			if (command_passthru == true and Rex::FileUtils.find_full_path(cmd))

				print_status("exec: #{line}")
				print_line('')

				self.busy = true
				begin
					io = ::IO.popen(line, "r")
					io.each_line do |data|
						print(data)
					end
					io.close
				rescue ::Errno::EACCES, ::Errno::ENOENT
					print_error("Permission denied exec: #{line}")
				end
				self.busy = false
				return
			end
		end

		super
	end

	##
	#
	# Handlers for various global configuration values
	#
	##

	#
	# SessionLogging.
	#
	def handle_session_logging(val)
		if (val =~ /^(y|t|1)/i)
			Msf::Logging.enable_session_logging(true)
			print_line("Session logging will be enabled for future sessions.")
		else
			Msf::Logging.enable_session_logging(false)
			print_line("Session logging will be disabled for future sessions.")
		end
	end

	#
	# ConsoleLogging.
	#
	def handle_console_logging(val)
		if (val =~ /^(y|t|1)/i)
			Msf::Logging.enable_log_source('console')
			print_line("Console logging is now enabled.")

			set_log_source('console')

			rlog("\n[*] Console logging started: #{Time.now}\n\n", 'console')
		else
			rlog("\n[*] Console logging stopped: #{Time.now}\n\n", 'console')

			unset_log_source

			Msf::Logging.disable_log_source('console')
			print_line("Console logging is now disabled.")
		end
	end

	#
	# This method handles adjusting the global log level threshold.
	#
	def handle_loglevel(val)
		set_log_level(Rex::LogSource, val)
		set_log_level(Msf::LogSource, val)
	end

end

#
# This exception is used to indicate that functionality is disabled due to
# defanged being true
#
class DefangedException < ::Exception
	def to_s
		"This functionality is currently disabled (defanged mode)"
	end
end

end
end
end
