# -*- coding: binary -*-
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

	end

	@@load_opts = Rex::Parser::Arguments.new(
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
			"use"        => "Deprecated alias for 'load'",
			"load"       => "Load one or more meterpreter extensions",
			"quit"       => "Terminate the meterpreter session",
			"resource"   => "Run the commands stored in a file",
			"read"       => "Reads data from a channel",
			"run"        => "Executes a meterpreter script or Post module",
			"bgrun"      => "Executes a meterpreter script as a background thread",
			"bgkill"     => "Kills a background meterpreter script",
			"bglist"     => "Lists running background scripts",
			"write"      => "Writes data to a channel",
			"enable_unicode_encoding"  => "Enables encoding of unicode strings",
			"disable_unicode_encoding" => "Disables encoding of unicode strings"
		}

		if client.passive_service
			c["detach"] = "Detach the meterpreter session (for http/https)"
		end
		# The only meterp that implements this right now is native Windows and for
		# whatever reason it is not adding core_migrate to its list of commands.
		# Use a dumb platform til it gets sorted.
		#if client.commands.include? "core_migrate"
		if client.platform =~ /win/
			c["migrate"] = "Migrate the server to another process"
		end

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

	def cmd_background_help
		print_line "Usage: background"
		print_line
		print_line "Stop interacting with this session and return to the parent prompt"
		print_line
	end

	def cmd_background
		print_status "Backgrounding session #{client.name}..."
		client.interacting = false
	end

	#
	# Displays information about active channels
	#
	@@channel_opts = Rex::Parser::Arguments.new(
		"-c" => [ true,  "Close the given channel." ],
		"-k" => [ true,  "Close the given channel." ],
		"-i" => [ true,  "Interact with the given channel." ],
		"-l" => [ false, "List active channels." ],
		"-r" => [ true,  "Read from the given channel." ],
		"-w" => [ true,  "Write to the given channel." ],
		"-h" => [ false, "Help menu." ])

	def cmd_channel_help
		print_line "Usage: channel [options]"
		print_line
		print_line "Displays information about active channels."
		print_line @@channel_opts.usage
	end

	#
	# Performs operations on the supplied channel.
	#
	def cmd_channel(*args)
		if args.empty? or args.include?("-h") or args.include?("--help")
			cmd_channel_help
			return
		end

		mode = nil
		chan = nil

		# Parse options
		@@channel_opts.parse(args) { |opt, idx, val|
			case opt
			when "-l"
				mode = :list
			when "-c", "-k"
				mode = :close
				chan = val
			when "-i"
				mode = :interact
				chan = val
			when "-r"
				mode = :read
				chan = val
			when "-w"
				mode = :write
				chan = val
			end
			if @@channel_opts.arg_required?(opt)
				unless chan
					print_error("Channel ID required")
					return
				end
			end
		}

		case mode
		when :list
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
		when :close
			cmd_close(chan)
		when :interact
			cmd_interact(chan)
		when :read
			cmd_read(chan)
		when :write
			cmd_write(chan)
		else
			# No mode, no service.
			return true
		end
	end

	def cmd_channel_tabs(str, words)
		case words.length
		when 1
			@@channel_opts.fmt.keys
		when 2
			case words[1]
			when "-k", "-c", "-i", "-r", "-w"
				tab_complete_channels
			else
				[]
			end
		else
			[]
		end
	end

	def cmd_close_help
		print_line "Usage: close <channel_id>"
		print_line
		print_line "Closes the supplied channel."
		print_line
	end

	#
	# Closes a supplied channel.
	#
	def cmd_close(*args)
		if (args.length == 0)
			cmd_close_help
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

	def cmd_close_tabs(str, words)
		return [] if words.length > 1

		return tab_complete_channels
	end

	#
	# Terminates the meterpreter session.
	#
	def cmd_exit(*args)
		print_status("Shutting down Meterpreter...")
		client.core.shutdown rescue nil
		client.shutdown_passive_dispatcher
		shell.stop
	end

	alias cmd_quit cmd_exit

	def cmd_detach_help
		print_line "Detach from the victim. Only possible for non-stream sessions (http/https)"
		print_line
		print_line "The victim will continue to attempt to call back to the handler until it"
		print_line "successfully connects (which may happen immediately if you have a handler"
		print_line "running in the background), or reaches its expiration."
		print_line
		print_line "This session may #{client.passive_service ? "" : "NOT"} be detached."
		print_line
	end

	#
	# Disconnects the session
	#
	def cmd_detach(*args)
		if not client.passive_service
			print_error("Detach is only possible for non-stream sessions (http/https)")
			return
		end
		client.shutdown_passive_dispatcher
		shell.stop
	end

	def cmd_interact_help
		print_line "Usage: interact <channel_id>"
		print_line
		print_line "Interacts with the supplied channel."
		print_line
	end

	#
	# Interacts with a channel.
	#
	def cmd_interact(*args)
		if (args.length == 0)
			cmd_info_help
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

	alias cmd_interact_tabs cmd_close_tabs

	#
	# Runs the IRB scripting shell
	#
	def cmd_irb(*args)
		print_status("Starting IRB shell")
		print_status("The 'client' variable holds the meterpreter client\n")

		Rex::Ui::Text::IrbShell.new(binding).run
	end

	def cmd_migrate_help
		print_line "Usage: migrate <pid>"
		print_line
		print_line "Migrates the server instance to another process."
		print_line "NOTE: Any open channels or other dynamic state will be lost."
		print_line
	end

	#
	# Migrates the server to the supplied process identifier.
	#
	# @param args [Array<String>] Commandline arguments, only -h or a pid
	# @return [void]
	def cmd_migrate(*args)
		if ( args.length == 0 or args.include?("-h") )
			cmd_migrate_help
			return true
		end

		pid = args[0].to_i
		if(pid == 0)
			print_error("A process ID must be specified, not a process name")
			return
		end

		begin
			server = client.sys.process.open
		rescue TimeoutError => e
			elog(e.to_s)
		rescue RequestError => e
			elog(e.to_s)
		end

		server ? print_status("Migrating from #{server.pid} to #{pid}...") : print_status("Migrating to #{pid}")

		# Do this thang.
		client.core.migrate(pid)

		print_status("Migration completed successfully.")
	end

	def cmd_load_help
		print_line("Usage: load ext1 ext2 ext3 ...")
		print_line
		print_line "Loads a meterpreter extension module or modules."
		print_line @@load_opts.usage
	end

	#
	# Loads one or more meterpreter extensions.
	#
	def cmd_load(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		@@load_opts.parse(args) { |opt, idx, val|
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
					cmd_load_help
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

	def cmd_load_tabs(str, words)
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

	def cmd_use(*args)
		#print_error("Warning: The 'use' command is deprecated in favor of 'load'")
		cmd_load(*args)
	end
	alias cmd_use_help cmd_load_help
	alias cmd_use_tabs cmd_load_tabs

	def cmd_read_help
		print_line "Usage: read <channel_id> [length]"
		print_line
		print_line "Reads data from the supplied channel."
		print_line
	end

	#
	# Reads data from a channel.
	#
	def cmd_read(*args)
		if (args.length == 0)
			cmd_read_help
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

	alias cmd_read_tabs cmd_close_tabs

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
				original_mod = mod
				reloaded_mod = client.framework.modules.reload_module(original_mod)

				unless reloaded_mod
					error = client.framework.modules.module_load_error_by_path[original_mod.file_path]
					print_error("Failed to reload module: #{error}")

					return
				end

				opts = (args + [ "SESSION=#{client.sid}" ]).join(',')
				reloaded_mod.run_simple(
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

	def cmd_info_help
		print_line 'Usage: info <module>'
		print_line
		print_line 'Prints information about a post-exploitation module'
		print_line
	end

	#
	# Show info for a given Post module.
	#
	# See also +cmd_info+ in lib/msf/ui/console/command_dispatcher/core.rb
	#
	def cmd_info(*args)
		return unless msf_loaded?

		if args.length != 1 or args.include?("-h")
			cmd_info_help
			return
		end

		module_name = args.shift
		mod = client.framework.modules.create(module_name);

		if mod.nil?
			print_error 'Invalid module: ' << module_name
		end

		if (mod)
			print_line(::Msf::Serializer::ReadableText.dump_module(mod))
			mod_opt = ::Msf::Serializer::ReadableText.dump_options(mod, '   ')
			print_line("\nModule options (#{mod.fullname}):\n\n#{mod_opt}") if (mod_opt and mod_opt.length > 0)
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

	def cmd_write_help
		print_line "Usage: write [options] channel_id"
		print_line
		print_line "Writes data to the supplied channel."
		print_line @@write_opts.usage
	end

	def cmd_write(*args)
		if (args.length == 0 or args.include?("-h"))
			cmd_write_help
			return
		end

		src_file = nil
		cid      = nil

		@@write_opts.parse(args) { |opt, idx, val|
			case opt
				when "-f"
					src_file = val
				else
					cid = val.to_i
			end
		}

		# Find the channel associated with this cid, assuming the cid is valid.
		if ((!cid) or (!(channel = client.find_channel(cid))))
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

	def cmd_resource_help
		print_line "Usage: resource <path1> [path2 ...]"
		print_line
		print_line "Run the commands stored in the supplied files."
		print_line
	end

	def cmd_resource(*args)
		if args.empty?
			return false
		end
		args.each do |glob|
			files = ::Dir.glob(::File.expand_path(glob))
			if files.empty?
				print_error("No such file #{glob}")
				next
			end
			files.each do |filename|
				print_status("Reading #{filename}")
				if (not ::File.readable?(filename))
					print_error("Could not read file #{filename}")
					next
				else
					::File.open(filename, "r").each_line do |line|
						next if line.strip.length < 1
						next if line[0,1] == "#"
						begin
							print_status("Running #{line}")
							client.console.run_multiple(line)
						rescue ::Exception => e
							print_error("Error Running Command #{line}: #{e.class} #{e}")
						end

					end
				end
			end
		end
	end

	def cmd_resource_tabs(str, words)
		return [] if words.length > 1

		tab_complete_filenames(str, words)
	end

	def cmd_enable_unicode_encoding
		client.encode_unicode = true
		print_status("Unicode encoding is enabled")
	end

	def cmd_disable_unicode_encoding
		client.encode_unicode = false
		print_status("Unicode encoding is disabled")
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
			else
				# the klass is already loaded, from a previous invocation
				loaded = true
				break
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
		tabs = client.framework.modules.post.map { |name,klass|
			mod = client.framework.modules.post.create(name)
			if mod and mod.session_compatible?(client)
				mod.fullname.dup
			else
				nil
			end
		}

		# nils confuse readline
		tabs.compact
	end

	def tab_complete_channels
		client.channels.keys.map { |k| k.to_s }
	end

end

end
end
end
end

