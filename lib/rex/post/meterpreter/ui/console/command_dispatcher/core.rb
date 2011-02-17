require 'rex/post/meterpreter'
require 'rex/parser/arguments'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Core meterpreter client commands that provide only the required set of
# commands for having a functional meterpreter client<->server instance.
#
###
class Console::CommandDispatcher::Core

	include Console::CommandDispatcher

	#
	# Initializes an instance of the core command set using the supplied shell
	# for interactivity.
	#
	def initialize(shell)
		super

		self.extensions = []
		self.bgjobs     = []
		self.bgjob_id   = 0

		@msf_loaded = nil
	end

	def msf_loaded?
		return @msf_loaded unless @msf_loaded.nil?
		# if we get here we must not have initialized yet

		if client.framework
			# We have a framework instance so the msf libraries should be
			# available.  Load up the ones we're going to use
			require 'msf/base/serializer/readable_text'
		end
		@msf_loaded = !!(client.framework)
		@msf_loaded
	end

	@@use_opts = Rex::Parser::Arguments.new(
		"-l" => [ false, "List all available extensions" ],
		"-h" => [ false, "Help menu."                    ])

	#
	# List of supported commands.
	#
	def commands
		c = {
			"?"          => "Help menu",
			"background" => "Backgrounds the current session",
			"close"      => "Closes a channel",
			"channel"    => "Displays information about active channels",
			"exit"       => "Terminate the meterpreter session",
			"help"       => "Help menu",
			"interact"   => "Interacts with a channel",
			"irb"        => "Drop into irb scripting mode",
			"migrate"    => "Migrate the server to another process",
			"use"        => "Load a one or more meterpreter extensions",
			"quit"       => "Terminate the meterpreter session",
			"read"       => "Reads data from a channel",
			"run"        => "Executes a meterpreter script or Post module",
			"bgrun"      => "Executes a meterpreter script as a background thread",
			"bgkill"     => "Kills a background meterpreter script",
			"bglist"     => "Lists running background scripts",
			"write"      => "Writes data to a channel",
		}
		if (msf_loaded?)
			c["info"] = "Displays information about a Post module"
		end

		c
	end

	#
	# Core baby.
	#
	def name
		"Core"
	end

	def cmd_background
		client.interacting = false
	end

	#
	# Displays information about active channels
	#
	@@channel_opts = Rex::Parser::Arguments.new(
		"-l" => [ false, "List active channels." ],
		"-h" => [ false, "Help menu."            ])

	#
	# Performs operations on the supplied channel.
	#
	def cmd_channel(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		mode = nil

		# Parse options
		@@channel_opts.parse(args) { |opt, idx, val|
			case opt
				when "-h"
					print(
						"Usage: channel [options]\n\n" +
						"Displays information about active channels.\n" +
						@@channel_opts.usage)
					return true
				when "-l"
					mode = 'list'
			end
		}

		# No mode, no service.
		if (mode == nil)
			return true
		elsif (mode == 'list')
			tbl = Rex::Ui::Text::Table.new(
				'Indent'  => 4,
				'Columns' =>
					[
						'Id',
						'Class',
						'Type'
					])
			items = 0

			client.channels.each_pair { |cid, channel|
				tbl << [ cid, channel.class.cls, channel.type ]
				items += 1
			}

			if (items == 0)
				print_line("No active channels.")
			else
				print("\n" + tbl.to_s + "\n")
			end
		end
	end

	#
	# Closes a supplied channel.
	#
	def cmd_close(*args)
		if (args.length == 0)
			print_line(
				"Usage: close channel_id\n\n" +
				"Closes the supplied channel.")
			return true
		end

		cid     = args[0].to_i
		channel = client.find_channel(cid)

		if (!channel)
			print_error("Invalid channel identifier specified.")
			return true
		else
			channel._close # Issue #410

			print_status("Closed channel #{cid}.")
		end
	end

	#
	# Terminates the meterpreter session.
	#
	def cmd_exit(*args)
		shell.stop
	end

	alias cmd_quit cmd_exit

	#
	# Interacts with a channel.
	#
	def cmd_interact(*args)
		if (args.length == 0)
			print_line(
				"Usage: interact channel_id\n\n" +
				"Interacts with the supplied channel.")
			return true
		end

		cid     = args[0].to_i
		channel = client.find_channel(cid)

		if (channel)
			print_line("Interacting with channel #{cid}...\n")

			shell.interact_with_channel(channel)
		else
			print_error("Invalid channel identifier specified.")
		end
	end

	#
	# Runs the IRB scripting shell
	#
	def cmd_irb(*args)
		print_status("Starting IRB shell")
		print_status("The 'client' variable holds the meterpreter client\n")

		Rex::Ui::Text::IrbShell.new(binding).run
	end

	#
	# Migrates the server to the supplied process identifier.
	#
	def cmd_migrate(*args)
		if (args.length == 0)
			print_line(
				"Usage: migrate pid\n\n" +
				"Migrates the server instance to another process.\n" +
				"Note: Any open channels or other dynamic state will be lost.")
			return true
		end

		pid = args[0].to_i
		if(pid == 0)
			print_error("A process ID must be specified, not a process name")
			return
		end

		print_status("Migrating to #{pid}...")

		# Do this thang.
		client.core.migrate(pid)

		print_status("Migration completed successfully.")
	end

	#
	# Loads one or more meterpreter extensions.
	#
	def cmd_use(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		modules = nil

		@@use_opts.parse(args) { |opt, idx, val|
			case opt
				when "-l"
					exts = []
					path = ::File.join(Msf::Config.install_root, 'data', 'meterpreter')
					::Dir.entries(path).each { |f|
						if (::File.file?(::File.join(path, f)) && f =~ /ext_server_(.*)\.#{client.binary_suffix}/ )
							exts.push($1)
						end
					}
					print(exts.sort.join("\n") + "\n")

					return true
				when "-h"
					print(
						"Usage: use ext1 ext2 ext3 ...\n\n" +
						"Loads a meterpreter extension module or modules.\n" +
						@@use_opts.usage)
					return true
			end
		}

		# Load each of the modules
		args.each { |m|
			md = m.downcase

			if (extensions.include?(md))
				print_error("The '#{md}' extension has already been loaded.")
				next
			end

			print("Loading extension #{md}...")

			begin
				# Use the remote side, then load the client-side
				if (client.core.use(md) == true)
					add_extension_client(md)
				end
			rescue
				print_line
				log_error("Failed to load extension: #{$!}")
				next
			end

			print_line("success.")
		}

		return true
	end

	def cmd_use_tabs(str, words)
		tabs = []
		path = ::File.join(Msf::Config.install_root, 'data', 'meterpreter')
		::Dir.entries(path).each { |f|
			if (::File.file?(::File.join(path, f)) && f =~ /ext_server_(.*)\.#{client.binary_suffix}/ )
				if (not extensions.include?($1))
					tabs.push($1)
				end
			end
		}
		return tabs
	end

	#
	# Reads data from a channel.
	#
	def cmd_read(*args)
		if (args.length == 0)
			print_line(
				"Usage: read channel_id [length]\n\n" +
				"Reads data from the supplied channel.")
			return true
		end

		cid     = args[0].to_i
		length  = (args.length >= 2) ? args[1].to_i : 16384
		channel = client.find_channel(cid)

		if (!channel)
			print_error("Channel #{cid} is not valid.")
			return true
		end

		data = channel.read(length)

		if (data and data.length)
			print("Read #{data.length} bytes from #{cid}:\n\n#{data}\n")
		else
			print_error("No data was returned.")
		end

		return true
	end

	def cmd_run_help
		print_line "Usage: run <script> [arguments]"
		print_line 
		print_line "Executes a ruby script or Metasploit Post module in the context of the"
		print_line "meterpreter session.  Post modules can take arguments in var=val format."
		print_line "Example: run post/foo/bar BAZ=abcd"
		print_line 
	end

	#
	# Executes a script in the context of the meterpreter session.
	#
	def cmd_run(*args)
		if args.length == 0
			cmd_run_help
			return true
		end

		# Get the script name
		begin
			script_name = args.shift
			# First try it as a Post module if we have access to the Metasploit
			# Framework instance.  If we don't, or if no such module exists,
			# fall back to using the scripting interface.
			if (msf_loaded? and mod = client.framework.modules.create(script_name))
				omod = mod
				mod = client.framework.modules.reload_module(mod)
				if (not mod)
					print_error("Failed to reload module: #{client.framework.modules.failed[omod.file_path]}")
					return
				end
				opts = (args + [ "SESSION=#{client.sid}" ]).join(',')
				mod.run_simple(
					#'RunAsJob' => true,
					'LocalInput'  => shell.input,
					'LocalOutput' => shell.output,
					'OptionStr'   => opts
				)
			else
				# the rest of the arguments get passed in through the binding
				client.execute_script(script_name, args)
			end
		rescue
			print_error("Error in script: #{$!.class} #{$!}")
			elog("Error in script: #{$!.class} #{$!}")
			dlog("Callstack: #{$@.join("\n")}")
		end
	end

	def cmd_run_tabs(str, words)
		tabs = []
		if(not words[1] or not words[1].match(/^\//))
			begin
				if (msf_loaded?)
					tabs += tab_complete_postmods
				end
				[
					::Msf::Sessions::Meterpreter.script_base,
					::Msf::Sessions::Meterpreter.user_script_base
				].each do |dir|
					next if not ::File.exist? dir
					tabs += ::Dir.new(dir).find_all { |e|
						path = dir + ::File::SEPARATOR + e
						::File.file?(path) and ::File.readable?(path)
					}
				end
			rescue Exception
			end
		end
		return tabs.map { |e| e.sub(/\.rb$/, '') }
	end


	#
	# Executes a script in the context of the meterpreter session in the background
	#
	def cmd_bgrun(*args)
		if args.length == 0
			print_line(
				"Usage: bgrun <script> [arguments]\n\n" +
				"Executes a ruby script in the context of the meterpreter session.")
			return true
		end

		jid = self.bgjob_id
		self.bgjob_id += 1

		# Get the script name
		self.bgjobs[jid] = Rex::ThreadFactory.spawn("MeterpreterBGRun(#{args[0]})-#{jid}", false, jid, args) do |myjid,xargs|
			::Thread.current[:args] = xargs.dup
			begin
				# the rest of the arguments get passed in through the binding
				client.execute_script(args.shift, args)
			rescue ::Exception
				print_error("Error in script: #{$!.class} #{$!}")
				elog("Error in script: #{$!.class} #{$!}")
				dlog("Callstack: #{$@.join("\n")}")
			end
			self.bgjobs[myjid] = nil
			print_status("Background script with Job ID #{myjid} has completed (#{::Thread.current[:args].inspect})")
		end

		print_status("Executed Meterpreter with Job ID #{jid}")
	end

	#
	# Map this to the normal run command tab completion
	#
	def cmd_bgrun_tabs(*args)
		cmd_run_tabs(*args)
	end

	#
	# Kill a background job
	#
	def cmd_bgkill(*args)
		if args.length == 0
			print_line("Usage: bgkill [id]")
			return
		end

		args.each do |jid|
			jid = jid.to_i
			if self.bgjobs[jid]
				print_status("Killing background job #{jid}...")
				self.bgjobs[jid].kill
				self.bgjobs[jid] = nil
			else
				print_error("Job #{jid} was not running")
			end
		end
	end

	#
	# List background jobs
	#
	def cmd_bglist(*args)
		self.bgjobs.each_index do |jid|
			if self.bgjobs[jid]
				print_status("Job #{jid}: #{self.bgjobs[jid][:args].inspect}")
			end
		end
	end

	#
	# Show info for a given Post module.  
	#
	# See also +cmd_info+ in lib/msf/ui/console/command_dispatcher/core.rb
	#
	def cmd_info(*args)
		return unless msf_loaded?

		if args.length != 1
			print_error 'Usage: info <module>'
			return
		end
		
		module_name = args.shift
		mod = client.framework.modules.create(module_name);
		
		if mod.nil?
			print_error 'Invalid module: ' << module_name
		end

		if (mod)
			print_line ::Msf::Serializer::ReadableText.dump_module(mod)
		end
	end

	def cmd_info_tabs(*args)
		return unless msf_loaded?
		tab_complete_postmods
	end

	#
	# Writes data to a channel.
	#
	@@write_opts = Rex::Parser::Arguments.new(
		"-f" => [ true,  "Write the contents of a file on disk" ],
		"-h" => [ false, "Help menu."                           ])

	def cmd_write(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		src_file = nil
		cid      = nil

		@@write_opts.parse(args) { |opt, idx, val|
			case opt
				when "-h"
					print(
						"Usage: write [options] channel_id\n\n" +
						"Writes data to the supplied channel.\n" +
						@@write_opts.usage)
					return true
				when "-f"
					src_file = val
				else
					cid = val.to_i
			end
		}

		# Find the channel associated with this cid, assuming the cid is valid.
		if ((!cid) or
		    (!(channel = client.find_channel(cid))))
			print_error("Invalid channel identifier specified.")
			return true
		end

		# If they supplied a source file, read in its contents and write it to
		# the channel
		if (src_file)
			begin
				data = ''

				::File.open(src_file, 'rb') { |f|
					data = f.read(f.stat.size)
				}

			rescue Errno::ENOENT
				print_error("Invalid source file specified: #{src_file}")
				return true
			end

			if (data and data.length > 0)
				channel.write(data)
				print_status("Wrote #{data.length} bytes to channel #{cid}.")
			else
				print_error("No data to send from file #{src_file}")
				return true
			end
		# Otherwise, read from the input descriptor until we're good to go.
		else
			print("Enter data followed by a '.' on an empty line:\n\n")

			data = ''

			# Keep truckin'
			while (s = shell.input.gets)
				break if (s =~ /^\.\r?\n?$/)
				data += s
			end

			if (!data or data.length == 0)
				print_error("No data to send.")
			else
				channel.write(data)
				print_status("Wrote #{data.length} bytes to channel #{cid}.")
			end
		end

		return true
	end

	@@client_extension_search_paths = [ ::File.join(Rex::Root, "post", "meterpreter", "ui", "console", "command_dispatcher") ]

	def self.add_client_extension_search_path(path)
		@@client_extension_search_paths << path unless @@client_extension_search_paths.include?(path)
	end
	def self.client_extension_search_paths
		@@client_extension_search_paths
	end

protected

	attr_accessor :extensions # :nodoc:
	attr_accessor :bgjobs, :bgjob_id # :nodoc:

	CommDispatcher = Console::CommandDispatcher

	#
	# Loads the client extension specified in mod
	#
	def add_extension_client(mod)
		loaded = false
		klass = nil
		self.class.client_extension_search_paths.each do |path|
			path = ::File.join(path, "#{mod}.rb")
			klass = CommDispatcher.check_hash(path)
			if (klass == nil)
				old   = CommDispatcher.constants
				next unless ::File.exist? path

				if (require(path))
					new  = CommDispatcher.constants
					diff = new - old

					next if (diff.empty?)

					klass = CommDispatcher.const_get(diff[0])

					CommDispatcher.set_hash(path, klass)
					loaded = true
					break
				else
					print_error("Failed to load client script file: #{path}")
					return false
				end
			end
		end
		unless loaded
			print_error("Failed to load client portion of #{mod}.")
			return false
		end

		# Enstack the dispatcher
		self.shell.enstack_dispatcher(klass)

		# Insert the module into the list of extensions
		self.extensions << mod
	end

	def tab_complete_postmods
		# XXX This might get slow with a large number of post
		# modules.  The proper solution is probably to implement a
		# Module::Post#session_compatible?(session_object_or_int) method
		tabs = client.framework.modules.post.map { |name,klass|
			mod = klass.new
			if mod.compatible_sessions.include?(client.sid)
				mod.fullname.dup
			else
				nil
			end
		}

		# nils confuse readline
		tabs.compact
	end

end

end
end
end
end

