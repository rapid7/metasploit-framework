require 'msf/core'
require 'msf/base'
require 'msf/ui'
require 'msf/ui/console/framework_event_manager'
require 'msf/ui/console/command_dispatcher'
require 'msf/ui/console/table'
require 'find'

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

	DefaultPrompt     = "%umsf"
	DefaultPromptChar = ">%c"

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
	def initialize(prompt = DefaultPrompt, prompt_char = DefaultPromptChar, opts = {})

		# Choose a readline library before calling the parent
		rl = false
		begin
			if(opts['RealReadline'])
				require 'readline'
				rl = true
			end
		rescue ::LoadError
		end
		
		# Default to the RbReadline wrapper		
		require 'readline_compatible' if(not rl)


		# Call the parent
		super(prompt, prompt_char)

		# Temporarily disable output
		self.disable_output = true

		# Load pre-configuration
		load_preconfig
	
		# Initialize attributes
		self.framework = opts['Framework'] || Msf::Simple::Framework.create
		
		# Initialize the user interface to use a different input and output
		# handle if one is supplied
		if (opts['LocalInput'] or opts['LocalOutput'])
			init_ui(
				opts['LocalInput'],
				opts['LocalOutput'])
		end

		# Add the core command dispatcher as the root of the dispatcher
		# stack
		enstack_dispatcher(CommandDispatcher::Core)
		
		# Add the database dispatcher if it is usable
		if(framework.db.usable)
			require 'msf/ui/console/command_dispatcher/db'
			enstack_dispatcher(CommandDispatcher::Db)
		else
			print_error("***")
			print_error("* WARNING: No database support: #{framework.db.error.class} #{framework.db.error}") 
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

		# Load console-specific configuration
		load_config(opts['Config'])
	
		# Re-enable output
		self.disable_output = false

		# Load additional modules as necessary
		self.framework.modules.add_module_path(opts['ModulePath'], false) if opts['ModulePath']

		# Process things before we actually display the prompt and get rocking
		on_startup

		# Process the resource script
		load_resource(opts['Resource'])

		# Whether or not command passthru should be allowed
		self.command_passthru = (opts['AllowCommandPassthru'] == false) ? false : true

		# Disables "dangerous" functionality of the console
		@defanged = opts['Defanged'] == true

		# If we're defanged, then command passthru should be disabled
		if @defanged
			self.command_passthru = false
		end
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
		return if not File.readable?(path)
		
		rcfd = File.open(path, 'r')
		rcfd.each_line do |line|
			line.strip!
			next if line.length == 0
			next if line =~ /^#/
			print_line("resource> #{line}")
			run_single(line)
		end
		rcfd.close
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
	def on_startup
		# Check for modules that failed to load
		if (framework.modules.failed.length > 0)
			print("[*] WARNING! The following modules could not be loaded!\n\n")
			framework.modules.failed.each_pair do |file, err|
				print("\t#{file}: #{err}\n\n")
			end
			print("\n")
		end
		
		# Build the banner message
		run_single("banner")
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
				
				if (framework and framework.modules.valid?(val) == false)
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
	# If defanged is true, dangerous functionality, such as exploitation, irb,
	# and command shell passthru is disabled.  In this case, an exception is 
	# raised.
	#
	def defanged?
		if @defanged
			raise DefangedException
		end
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
				io = ::IO.popen(line, "r")
				io.each_line do |data|
					print(data)
				end
				io.close
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
