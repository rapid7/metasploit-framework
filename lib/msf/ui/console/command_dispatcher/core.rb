require 'msf/ui/console/command_dispatcher/encoder'
require 'msf/ui/console/command_dispatcher/exploit'
require 'msf/ui/console/command_dispatcher/nop'
require 'msf/ui/console/command_dispatcher/payload'
require 'msf/ui/console/command_dispatcher/auxiliary'

module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Command dispatcher for core framework commands, such as module loading,
# session interaction, and other general things.
#
###
class Core

	include Msf::Ui::Console::CommandDispatcher

	# Session command options
	@@sessions_opts = Rex::Parser::Arguments.new(
		"-i" => [ true,  "Interact with the supplied session identifier." ],
		"-h" => [ false, "Help banner."                                   ],
		"-l" => [ false, "List all active sessions."                      ],
		"-v" => [ false, "List verbose fields."                           ],
		"-q" => [ false, "Quiet mode."                                    ],
		"-d" => [  true, "Detach an interactive session"                  ],
		"-k" => [  true, "Terminate session."                             ])

	@@jobs_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help banner."                                   ],
		"-k" => [ true,  "Terminate the specified job name."              ],
		"-K" => [ false, "Terminate all running jobs."                    ],
		"-l" => [ false, "List all running jobs."                         ])
	
	@@persist_opts = Rex::Parser::Arguments.new(
		"-s" => [ true,  "Storage medium to be used (ex: flatfile)."      ],
		"-r" => [ false, "Restore framework state."                       ],
		"-h" => [ false, "Help banner."                                   ])

	@@connect_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help banner."                                   ],
		"-p" => [ true,  "List of proxies to use."                        ],
		"-C" => [ false, "Try to use CRLF for EOL sequence."              ],
		"-c" => [ true,  "Specify which Comm to use."                     ],
		"-i" => [ true,  "Send the contents of a file."                   ],
		"-P" => [ true,  "Specify source port."                           ],
		"-S" => [ true,  "Specify source address."                        ],
		"-s" => [ false, "Connect with SSL."                              ],
		"-w" => [ true,  "Specify connect timeout."                       ],
		"-z" => [ false, "Just try to connect, then return."              ])

	# The list of data store elements that cannot be set when in defanged
	# mode.
	DefangedProhibitedDataStoreElements = [ "ModulePaths" ]

	# Returns the list of commands supported by this command dispatcher
	def commands
		{
			"?"        => "Help menu",
			"back"     => "Move back from the current context",
			"banner"   => "Display an awesome metasploit banner",
			"cd"       => "Change the current working directory",
			"connect"  => "Communicate with a host",
			"exit"     => "Exit the console",
			"help"     => "Help menu",
			"info"     => "Displays information about one or more module",
			"irb"      => "Drop into irb scripting mode",
			"jobs"     => "Displays and manages jobs",
			"load"     => "Load a framework plugin",

# XXX complete this before re-enabling
#			"persist"  => "Persist or restore framework state information",

			"loadpath" => "Searches for and loads modules from a path",
			"quit"     => "Exit the console",
			"resource" => "Run the commands stored in a file",
			"route"    => "Route traffic through a session",
			"save"     => "Saves the active datastores",
			"search"   => "Searches module names and descriptions",
			"sessions" => "Dump session listings and display information about sessions",
			"set"      => "Sets a variable to a value",
			"setg"     => "Sets a global variable to a value",
			"show"     => "Displays modules of a given type, or all modules",
			"sleep"    => "Do nothing for the specified number of seconds",
			"unload"   => "Unload a framework plugin",
			"unset"    => "Unsets one or more variables",
			"unsetg"   => "Unsets one or more global variables",
			"use"      => "Selects a module by name",
			"version"  => "Show the framework and console library version numbers",
		}
	end

	#
	# Initializes the datastore cache
	#
	def initialize(driver)
		super

		@dscache = {}
	end

	#
	# Returns the name of the command dispatcher.
	#
	def name
		"Core"
	end

	def cmd_resource(*args)
		if args.empty?
			print(
				"Usage: resource path1 path2 ...\n\n" +
				"Run the commands stored in the supplied files.\n")
			return false
		end
		args.each { |res| driver.load_resource(res) }
	end


	#
	# Pop the current dispatcher stack context, assuming it isn't pointed at
	# the core stack context.
	#
	def cmd_back(*args)
		if (driver.dispatcher_stack.size > 1 and
		    driver.current_dispatcher.name != 'Core')
			# Reset the active module if we have one
			if (active_module)
				
				# Do NOT reset the UI anymore
				# active_module.reset_ui

				# Save the module's datastore so that we can load it later 
				# if the module is used again
				@dscache[active_module.fullname] = active_module.datastore.dup

				self.active_module = nil
			end

			# Destack the current dispatcher
			driver.destack_dispatcher
	
			# Restore the prompt
			driver.update_prompt
		end
	end


	#
	# Change the current working directory
	#
	def cmd_cd(*args)
		if(args.length == 0)
			print_error("No path specified")
			return
		end
		
		begin
			Dir.chdir(args.join(" ").strip)
		rescue ::Exception
			print_error("The specified path does not exist")
		end
	end
	
	#
	# Display one of the fabulous banners.
	#
	def cmd_banner(*args)
		banner  = Banner.to_s + "\n\n"
		banner << "       =[ msf v#{Msf::Framework::Version}\n"
		banner << "+ -- --=[ "
		banner << "#{framework.stats.num_exploits} exploits - "
		banner << "#{framework.stats.num_payloads} payloads\n"
		banner << "+ -- --=[ "
		banner << "#{framework.stats.num_encoders} encoders - "
		banner << "#{framework.stats.num_nops} nops\n"
		banner << "       =[ "
		banner << "#{framework.stats.num_auxiliary} aux\n"
		banner << "\n"

		# Display the banner
		print(banner)
	end

	#
	# Talk to a host
	#
	def cmd_connect(*args)
		if args.length < 2 or args.include?("-h")
			print(  "Usage: connect [options] <host> <port>\n\n" +
				"Communicate with a host, similar to interacting via netcat.\n" +
				@@connect_opts.usage)
			return false
		end

		crlf = false
		commval = nil
		fileval = nil
		proxies = nil
		srcaddr = nil
		srcport = nil
		ssl = false
		cto = nil
		justconn = false
		aidx = 0

		@@connect_opts.parse(args) do |opt, idx, val|
			case opt
				when "-C"
					crlf = true
					aidx = idx + 1
				when "-c"
					commval = val
					aidx = idx + 2
				when "-i"
					fileval = val
					aidx = idx + 2
				when "-P"
					srcport = val
					aidx = idx + 2
				when "-p"
					proxies = val
					aidx = idx + 2
				when "-S"
					srcaddr = val
					aidx = idx + 2
				when "-s"
					ssl = true
					aidx = idx + 1
				when "-w"
					cto = val.to_i
					aidx = idx + 2
				when "-z"
					justconn = true
					aidx = idx + 1
			end
		end

		commval = "Local" if commval =~ /local/i

		if fileval
			begin
				raise "Not a file" if File.ftype(fileval) != "file"
				infile = ::File.open(fileval)
			rescue
				print_error("Can't read from '#{fileval}': #{$!}")
				return false
			end
		end

		args = args[aidx .. -1]

		if args.length < 2
			print_error("You must specify a host and port")
			return false
		end

		host = args[0]
		port = args[1]

		comm = nil

		if commval
			begin
				if Rex::Socket::Comm.const_defined?(commval)
					comm = Rex::Socket::Comm.const_get(commval)
				end
			rescue NameError
			end

			if not comm
				session = framework.sessions.get(commval)

				if session.kind_of?(Msf::Session::Comm)
					comm = session
				end
			end

			if not comm
				print_error("Invalid comm '#{commval}' selected")
				return false
			end
		end

		begin
			sock = Rex::Socket::Tcp.create({
				'Comm'      => comm,
				'Proxies'   => proxies,
				'SSL'       => ssl,
				'PeerHost'  => host,
				'PeerPort'  => port,
				'LocalHost' => srcaddr,
				'LocalPort' => srcport,
				'Timeout'   => cto
			})
		rescue
			print_error("Unable to connect: #{$!}")
			return false
		end

		print_status("Connected to #{host}:#{port}")

		if justconn
			sock.close
			infile.close if infile
			return true
		end

		cin = infile || driver.input
		cout = driver.output

		begin
			# Console -> Network
			c2n = Thread.new(cin, sock) do |input, output|
				while true
					begin
						res = input.gets
						break if not res
						if crlf and (res =~ /^\n$/ or res =~ /[^\r]\n$/)
							res.gsub!(/\n$/, "\r\n")
						end
						output.write res
					rescue ::EOFError, ::IOError
						break
					end
				end
			end

			# Network -> Console
			n2c = Thread.new(sock, cout, c2n) do |input, output, cthr|
				while true
					begin
						res = input.read(65535)
						break if not res
						output.print res
					rescue ::EOFError, ::IOError
						break
					end
				end

				Thread.kill(cthr)
			end

			c2n.join

		rescue Interrupt
			c2n.kill
			n2c.kill
		end

		sock.close if not sock.closed?
		infile.close if infile

		true
	end

	#
	# Instructs the driver to stop executing.
	#
	def cmd_exit(*args)
		driver.stop
	end

	alias cmd_quit cmd_exit

	#
	# Causes process to pause for the specified number of seconds
	#
	def cmd_sleep(*args)
		return if not (args and args.length == 1)
		Rex::ThreadSafe.sleep(args[0].to_f)
	end
	
	#
	# Displays the command help banner or an individual command's help banner
	# if we can figure out how to invoke it.
	#
	def cmd_help(*args)
		if args and args.length > 0 and commands.include?(args[0])
			if self.respond_to? "cmd_"+ args[0] + "_help"
				self.send("cmd_"+ args[0] + "_help")
			else
				#
				# This part is done in a hackish way because not all of the
				# usage info is available from self.commands() or @@*_opts, so
				# we check @@<cmd>_opts for "-h".  It's non-optimal because
				# several commands have usage info, but don't use -h to invoke
				# it.
				begin
					opts = eval("@@" + args[0] + "_opts")
				rescue
				end
				if opts and opts.include?("-h")
					self.send("cmd_" + args[0], "-h")
				else
					print_line("No help available for #{args[0]}")
				end
			end
		else
			print(driver.help_to_s)
		end
	end
	def cmd_help_tabs(str, words)
		return commands.keys
	end


	alias cmd_? cmd_help

	#
	# Displays information about one or more module.
	#
	def cmd_info(*args)
		if (args.length == 0)
			if (active_module)
				print(Serializer::ReadableText.dump_module(active_module))
				return true
			else
				print(
					"Usage: info mod1 mod2 mod3 ...\n\n" +
					"Queries the supplied module or modules for information.\n")
				return false
			end
		end

		args.each { |name|
			mod = framework.modules.create(name)

			if (mod == nil)
				print_error("Invalid module: #{name}")
			else
				print(Serializer::ReadableText.dump_module(mod))
			end
		}
	end
	
	#
	# Tab completion for the info command (same as use)
	#
	def cmd_info_tabs(str, words)
		cmd_use_tabs(str, words)
	end	

	#
	# Goes into IRB scripting mode
	#
	def cmd_irb(*args)
		defanged?

		print_status("Starting IRB shell...\n")

		begin
			Rex::Ui::Text::IrbShell.new(binding).run
		rescue
			print_error("Error during IRB: #{$!}\n\n#{$@.join("\n")}")
		end
		
		# Reset tab completion
		if (driver.input.supports_readline)
			driver.input.reset_tab_completion
		end		
	end

	#
	# Displays and manages running jobs for the active instance of the
	# framework.
	#
	def cmd_jobs(*args)
		if (args.length == 0)
			args.unshift("-l")
		end

		# Parse the command options
		@@jobs_opts.parse(args) { |opt, idx, val|
			case opt
				when "-l"
					print("\n" +
						Serializer::ReadableText.dump_jobs(framework) + "\n")

				# Terminate the supplied job name
				when "-k"
					print_line("Stopping job: #{val}...")
					framework.jobs.stop_job(val)
					
				when "-K"
					print_line("Stopping all jobs...")
					framework.jobs.each_key do |i|
						framework.jobs.stop_job(i)
					end

				when "-h"
					print(
						"Usage: jobs [options]\n\n" +
						"Active job manipulation and interaction.\n" +
						@@jobs_opts.usage())
					return false
			end
		}
	end
	
	#
	# Tab completion for the jobs command
	#
	def cmd_jobs_tabs(str, words)
		if(not words[1])
			return %w{-l -k -K -h}
		end
		if (words[1] == '-k')
			# XXX return the list of job values
			ret = []
			framework.jobs.each_key do |i|
				ret.push i
			end
			return ret
		end
	end	
	
	#
	# Loads a plugin from the supplied path.  If no absolute path is supplied,
	# the framework root plugin directory is used.
	#
	def cmd_load(*args)
		defanged?

		if (args.length == 0)
			print_line(
				"Usage: load <path> [var=val var=val ...]\n\n" +
				"Load a plugin from the supplied path.  The optional\n" +
				"var=val options are custom parameters that can be\n" +
				"passed to plugins.")
			return false
		end

		# Default to the supplied argument path.
		path = args.shift
		opts  = {
			'LocalInput'    => driver.input,
			'LocalOutput'   => driver.output,
			'ConsoleDriver' => driver
			}

		# Parse any extra options that should be passed to the plugin
		args.each { |opt|
			k, v = opt.split(/=/)

			opts[k] = v if (k and v)
		}

		# If no absolute path was supplied, use the plugin directory as a base.
		path = Msf::Config.plugin_directory + File::SEPARATOR + path if (path !~ /#{File::SEPARATOR}/)

		# Load that plugin!
		begin
			if (inst = framework.plugins.load(path, opts))
				print_status("Successfully loaded plugin: #{inst.name}")
			end
		rescue ::Exception => e
			elog("Error loading plugin #{path}: #{e}\n\n#{e.backtrace.join("\n")}", src = 'core', level = 0, from = caller)
			print_error("Failed to load plugin from #{path}: #{e}")
		end
	end
	
	#
	# Tab completion for the load command
	#
	def cmd_load_tabs(str, words)
		if(not words[1] or not words[1].match(/^\//))
			begin
				return Dir.new(Msf::Config.plugin_directory).find_all { |e|
					path = Msf::Config.plugin_directory + File::SEPARATOR + e
					File.file?(path) and File.readable?(path)
				}.map { |e|
					e.sub!(/\.rb$/, '')
				}
			rescue Exception
			end
		end
	end	

	#
	# This method persists or restores framework state from a persistent
	# storage medium, such as a flatfile.
	#
	def cmd_persist(*args)
		defanged?

		if (args.length == 0)
			args.unshift("-h")
		end

		arg_idx = 0
		restore = false
		storage = 'flatfile'

		@@persist_opts.parse(args) { |opt, idx, val|
			case opt
				when "-s"
					storage = val
					arg_idx = idx + 2
				when "-r"
					restore = true
					arg_idx = idx + 1
				when "-h"
					print(
						"Usage: persist [-r] -s storage arg1 arg2 arg3 ...\n\n" +
						"Persist or restore framework state information.\n" +
						@@persist_opts.usage())
					return false
			end
		}

		# Chop off all the non-arguments
		args = args[arg_idx..-1]

		begin
			if (inst = Msf::PersistentStorage.create(storage, *args))
				inst.store(framework)
			else
				print_error("Failed to find storage medium named '#{storage}'")
			end
		rescue
			log_error("Failed to persist to #{storage}: #{$!}")
		end
	end

	#
	# Tab completion for the persist command
	#
	def cmd_persist_tabs(str, words)
		if (not words[1])
			return %w{-s -r -h}
		end	
	end
	
	#
	# This method handles the route command which allows a user to specify
	# which session a given subnet should route through.
	#
	def cmd_route(*args)
		if (args.length == 0)
			print(
				"Usage: route [add/remove/get/flush/print] subnet netmask [comm/sid]\n\n" +
				"Route traffic destined to a given subnet through a supplied session. \n" +
				"The default comm is Local.\n")
			return false
		end

		case args.shift
			when "add"
				if (args.length < 3)
					print_error("Missing arguments to route add.")
					return false
				end

				gw = nil

				# Satisfy case problems
				args[2] = "Local" if (args[2] =~ /local/i)

				begin
					# If the supplied gateway is a global Comm, use it.
					if (Rex::Socket::Comm.const_defined?(args[2]))
						gw = Rex::Socket::Comm.const_get(args[2])
					end
				rescue NameError
				end

				# If we still don't have a gateway, check if it's a session.
				if ((gw == nil) and
				    (session = framework.sessions.get(args[2])) and
				    (session.kind_of?(Msf::Session::Comm)))
					gw = session
				elsif (gw == nil)
					print_error("Invalid gateway specified.")
					return false
				end

				Rex::Socket::SwitchBoard.add_route(
					args[0],
					args[1],
					gw)
			when "remove"
				if (args.length < 3)
					print_error("Missing arguments to route remove.")
					return false
				end
				
				gw = nil

				# Satisfy case problems
				args[2] = "Local" if (args[2] =~ /local/i)

				begin
					# If the supplied gateway is a global Comm, use it.
					if (Rex::Socket::Comm.const_defined?(args[2]))
						gw = Rex::Socket::Comm.const_get(args[2])
					end
				rescue NameError
				end

				# If we still don't have a gateway, check if it's a session.
				if ((gw == nil) and
				    (session = framework.sessions.get(args[2])) and
				    (session.kind_of?(Msf::Session::Comm)))
					gw = session
				elsif (gw == nil)
					print_error("Invalid gateway specified.")
					return false
				end

				Rex::Socket::SwitchBoard.remove_route(
					args[0],
					args[1],
					gw)
			when "get"
				if (args.length == 0)
					print_error("You must supply an IP address.")
					return false
				end

				comm = Rex::Socket::SwitchBoard.best_comm(args[0])

				if ((comm) and
				    (comm.kind_of?(Msf::Session)))
					print_line("#{args[0]} routes through: Session #{comm.sid}")
				else
					print_line("#{args[0]} routes through: Local")
				end
			when "flush"
				Rex::Socket::SwitchBoard.flush_routes
			when "print"
				tbl =	Table.new(
					Table::Style::Default,
					'Header'  => "Active Routing Table",
					'Prefix'  => "\n",
					'Postfix' => "\n",
					'Columns' => 
						[
							'Subnet',
							'Netmask',
							'Gateway',
						],
					'ColProps' =>
						{
							'Subnet'  => { 'MaxWidth' => 17 },
							'Netmask' => { 'MaxWidth' => 17 },
						})

				Rex::Socket::SwitchBoard.each { |route|

					if (route.comm.kind_of?(Msf::Session))
						gw = "Session #{route.comm.sid}"
					else
						gw = route.comm.name.split(/::/)[-1]
					end

					tbl << [ route.subnet, route.netmask, gw ]
				}

				print(tbl.to_s)
		end
	end
	
	#
	# Tab completion for the route command
	#
	def cmd_route_tabs(str, words)
		if (not words[1])
			return %w{add remove get flush print}
		end
	end

	#
	# Saves the active datastore contents to disk for automatic use across
	# restarts of the console.
	#
	def cmd_save(*args)
		defanged?

		# Save the console config
		driver.save_config

		# Save the framework's datastore
		begin
			framework.save_config
	
			if (active_module)
				active_module.save_config
			end
		rescue
			log_error("Save failed: #{$!}")
			return false
		end
	
		print_line("Saved configuration to: #{Msf::Config.config_file}")
	end

	#
	# Adds one or more search paths.
	#
	def cmd_loadpath(*args)
		defanged?

		if (args.length == 0)
			print_error("No search paths were provided.")
			return true
		end

		totals    = {}
		overall   = 0
		curr_path = nil

		begin 
			# Walk the list of supplied search paths attempting to add each one
			# along the way
			args.each { |path|
				curr_path = path

				# Load modules, but do not consult the cache
				if (counts = framework.modules.add_module_path(path, false))
					counts.each_pair { |type, count|
						totals[type] = (totals[type]) ? (totals[type] + count) : count
	
						overall += count
					}
				end
			}
		rescue NameError
			log_error("Failed to add search path #{curr_path}: #{$!}")
			return true
		end

		added = "Loaded #{overall} modules:\n"

		totals.each_pair { |type, count|
			added << "    #{count} #{type}#{count != 1 ? 's' : ''}\n"
		}

		print(added)
	end

	def cmd_loadpath_tabs(str, words)
		paths = []
		if (File.directory?(str))
			paths = Dir.entries(str)
			paths = paths.map { |f|
				if File.directory? File.join(str,f)
					File.join(str,f)
				end
			}
			paths.delete_if { |f| f.nil? or File.basename(f) == '.' or File.basename(f) == '..' }
		else
			d = Dir.glob(str + "*").map { |f| f if File.directory?(f) }
			d.delete_if { |f| f.nil? or f == '.' or f == '..' }
			# If there's only one possibility, descend to the next level
			if (1 == d.length)
				paths = Dir.entries(d[0])
				paths = paths.map { |f|
					if File.directory? File.join(d[0],f)
						File.join(d[0],f)
					end
				}
				paths.delete_if { |f| f.nil? or File.basename(f) == '.' or File.basename(f) == '..' }
			else
				paths = d
			end
		end
		paths.sort!
		return paths
	end

	#
	# Searches modules (name and description) for specified regex
	#
	def cmd_search(*args)
		case args.length
			when 1
				section = 'all'
				match = args[0]
			when 2
				section = args[0]
				match = args[1]
			else
				print_line("Usage: search (all|encoders|nops|exploits|payloads|auxiliary) regex")
				return
		end

		begin
			regex = Regexp.new(match, true)
		rescue RegexpError => e
			print_error("Invalid regular expression: #{match} (hint: try .*)")
			return
		end

		print_status("Searching loaded modules for pattern '#{match}'...")
		
		case section
			when 'all'
				show_encoders(regex)
				show_nops(regex)
				show_exploits(regex)
				show_payloads(regex)
				show_auxiliary(regex)
			when 'encoders'
				show_encoders(regex)
			when 'nops'
				show_nops(regex)
			when 'exploits'
				show_exploits(regex)
			when 'payloads'
				show_payloads(regex)
			when 'auxiliary'
				show_auxiliary(regex)
			else
				print_line("Usage: search (all|encoders|nops|exploits|payloads|auxiliary) regex")
		end
	end
	
	#
	#
	# Provides an interface to the sessions currently active in the framework.
	#
	def cmd_sessions(*args)
		begin
		method  = 'list'
		quiet   = false
		verbose = false
		sid     = nil

		# Parse the command options
		@@sessions_opts.parse(args) { |opt, idx, val|
			case opt
				when "-q"
					quiet = true

				when "-v"
					verbose = true

				# Interact with the supplied session identifier
				when "-i"
					method = 'interact'
					sid    = val

				# Display the list of active sessions
				when "-l"
					method = 'list'

				when "-k"
					method = 'kill'
					sid = val
				
				when "-d"
					method = 'detach'
					sid = val
					
				# Display help banner
				when "-h"
					print(
						"Usage: sessions [options]\n\n" +
						"Active session manipulation and interaction.\n" +
						@@sessions_opts.usage())
					return false
			end
		}
	
		# Now, perform the actual method
		case method
		
			when 'kill'
				if ((session = framework.sessions.get(sid)))
					print_status("Killing session #{sid}")
					session.kill
				end
				
			when 'detach'
				if ((session = framework.sessions.get(sid)))
					print_status("Detaching session #{sid}")
					if (session.interactive?)				
						session.detach()
					end
				end
				
			when 'interact'
				if ((session = framework.sessions.get(sid)))
					if (session.interactive?)
						print_status("Starting interaction with #{session.name}...\n") if (quiet == false)

						self.active_session = session

						session.interact(driver.input.dup, driver.output)
		
						self.active_session = nil
						
						if (driver.input.supports_readline)
							driver.input.reset_tab_completion
						end
						
					else
						print_error("Session #{sid} is non-interactive.")
					end
				else
					print_error("Invalid session identifier: #{sid}")
				end
			when 'list'
					print("\n" + 
						Serializer::ReadableText.dump_sessions(framework, verbose) + "\n")
		end

		rescue IOError, EOFError, Rex::StreamClosedError
			print_status("Session stream closed.")
		rescue ::Interrupt
			raise $!
		rescue ::Exception
			log_error("Session manipulation failed: #{$!} #{$!.backtrace.inspect}")
		end

		# Reset the active session
		self.active_session = nil
		
		return true
	end

	#
	# Tab completion for the sessions command
	#
	def cmd_sessions_tabs(str, words)
		if (not words[1])
			return %w{-q -i -l -h}
		end
	end
	
	#
	# Sets a name to a value in a context aware environment.
	#
	def cmd_set(*args)
	
		# Figure out if these are global variables
		global = false

		if (args[0] == '-g')
			args.shift
			global = true
		end

		# Determine which data store we're operating on
		if (active_module and global == false)
			datastore = active_module.datastore
		else
			global = true
			datastore = self.framework.datastore
		end

		# Dump the contents of the active datastore if no args were supplied
		if (args.length == 0)
			# If we aren't dumping the global data store, then go ahead and
			# dump it first
			if (!global)
				print("\n" +
					Msf::Serializer::ReadableText.dump_datastore(
						"Global", framework.datastore))
			end

			# Dump the active datastore
			print("\n" +
				Msf::Serializer::ReadableText.dump_datastore(
					(global) ? "Global" : "Module: #{active_module.refname}",
					datastore) + "\n")
			return true
		elsif (args.length == 1)
			if (not datastore[args[0]].nil?)
				print_line("#{args[0]} => #{datastore[args[0]]}")
				return true
			else
				print_error("Unknown variable")
				print(
					"Usage: set name value\n\n" +
					"Sets an arbitrary name to an arbitrary value.\n")
				return false
			end
		end

		# Set the supplied name to the supplied value
		name  = args[0]
		value = args[1, args.length-1].join(' ')

		# Security check -- make sure the data store element they are setting
		# is not prohibited
		if global and DefangedProhibitedDataStoreElements.include?(name)
			defanged?
		end

		# If the driver indicates that the value is not valid, bust out.
		if (driver.on_variable_set(global, name, value) == false)
			print_error("The value specified for #{name} is not valid.")
			return true
		end

		datastore[name] = value

		print_line("#{name} => #{value}")
	end
	
	#
	# Tab completion for the set command
	#
	def cmd_set_tabs(str, words)
	
		# A value has already been specified
		if (words[2])
			return nil
		end
		
		# A value needs to be specified
		if(words[1])
			return tab_complete_option(str, words)
		end
		
		res = cmd_unset_tabs(str, words) || [ ]
		mod = active_module
		
		if (not mod)
			return res
		end
		
		mod.options.sorted.each { |e|
			name, opt = e
			res << name
		}
		
		# Exploits provide these three default options
		if (mod.exploit?)
			res << 'PAYLOAD'
			res << 'NOP'
			res << 'TARGET'
		end
		if (mod.exploit? or mod.payload?)
			res << 'ENCODER'
		end

		if (mod.auxiliary?)
			res << "ACTION"
		end

		if (mod.exploit? and mod.datastore['PAYLOAD'])
			p = framework.modules.create(mod.datastore['PAYLOAD'])
			if (p)
				p.options.sorted.each { |e|
					name, opt = e
					res << name
				}				
			end
		end

		return res
	end

		
	#
	# Sets the supplied variables in the global datastore.
	#
	def cmd_setg(*args)
		args.unshift('-g')

		cmd_set(*args)
	end
	
	#
	# Tab completion for the setg command
	#
	def cmd_setg_tabs(str, words)
		res = cmd_set_tabs(str, words) || [ ]
	end
	
	#
	# Displays the list of modules based on their type, or all modules if
	# no type is provided.
	#
	def cmd_show(*args)
		mod = self.active_module

		args << "all" if (args.length == 0)

		args.each { |type|
			case type
				when 'all'
					show_encoders
					show_nops
					show_exploits
					show_payloads
					show_auxiliary
					show_plugins
				when 'encoders'
					show_encoders
				when 'nops'
					show_nops
				when 'exploits'
					show_exploits
				when 'payloads'
					show_payloads
				when 'auxiliary'
					show_auxiliary
				when 'options'
					if (mod)
						show_options(mod)
					else
						print_error("No module selected.")
					end
				when 'advanced'
					if (mod)
						show_advanced_options(mod)
					else
						print_error("No module selected.")
					end
				when 'evasion'
					if (mod)
						show_evasion_options(mod)
					else
						print_error("No module selected.")
					end					
				when "plugins"
					show_plugins
				when "targets"
					if (mod and mod.exploit?)
						show_targets(mod)
					else
						print_error("No exploit module selected.")
					end
				when "actions"
					if (mod and mod.auxiliary?)
						show_actions(mod)
					else
						print_error("No auxiliary module selected.")
					end
			end
		}
	end
	
	#
	# Tab completion for the show command
	#
	def cmd_show_tabs(str, words)
		res = %w{all encoders nops exploits payloads auxiliary plugins}
		if (active_module)
			res.concat(%w{ options advanced evasion targets actions })
		end
		return res
	end
	
	#
	# Unloads a plugin by its name.
	#
	def cmd_unload(*args)
		if (args.length == 0)
			print_line(
				"Usage: unload [plugin name]\n\n" +
				"Unloads a plugin by its symbolic name.")
			return false
		end

		# Walk the plugins array
		framework.plugins.each { |plugin|
			# Unload the plugin if it matches the name we're searching for
			if (plugin.name == args[0])
				print("Unloading plugin #{args[0]}...")
				framework.plugins.unload(plugin)
				print_line("unloaded.")
				break
			end
		}
	end
	
	#
	# Tab completion for the unload command
	#
	def cmd_unload_tabs(str, words)
		tabs = []
		framework.plugins.each { |k| tabs.push(k.name) }
		return tabs
	end

	#
	# Unsets a value if it's been set.
	#
	def cmd_unset(*args)

		# Figure out if these are global variables
		global = false

		if (args[0] == '-g')
			args.shift
			global = true
		end

		# Determine which data store we're operating on
		if (active_module and global == false)
			datastore = active_module.datastore
		else
			datastore = framework.datastore
		end

		# No arguments?  No cookie.
		if (args.length == 0)
			print(
				"Usage: unset var1 var2 var3 ...\n\n" +
				"The unset command is used to unset one or more variables.\n" +
				"To flush all entires, specify 'all' as the variable name\n")

			return false
		end

		# If all was specified, then flush all of the entries
		if args[0] == 'all'
			print_line("Flushing datastore...")

			# Re-import default options into the module's datastore
			if (active_module and global == false)
				active_module.import_defaults
			# Or simply clear the global datastore
			else
				datastore.clear
			end

			return true
		end

		while ((val = args.shift))
			if (driver.on_variable_unset(global, val) == false)
				print_error("The variable #{val} cannot be unset at this time.")
				next
			end

			print_line("Unsetting #{val}...")

			datastore.delete(val)
		end
	end
	
	#
	# Tab completion for the unset command
	#
	def cmd_unset_tabs(str, words)
		datastore = active_module ? active_module.datastore : self.framework.datastore
		datastore.keys
	end
	
	#
	# Unsets variables in the global data store.
	#
	def cmd_unsetg(*args)
		args.unshift('-g')

		cmd_unset(*args)
	end
	
	#
	# Tab completion for the unsetg command
	#
	def cmd_unsetg_tabs(str, words)
		self.framework.datastore.keys
	end
	
	#
	# Uses a module.
	#
	def cmd_use(*args)
		if (args.length == 0)
			print(
				"Usage: use module_name\n\n" +
				"The use command is used to interact with a module of a given name.\n")
			return false
		end

		# Try to create an instance of the supplied module name
		mod_name = args[0]

		begin
			if ((mod = framework.modules.create(mod_name)) == nil)
				print_error("Failed to load module: #{mod_name}")
				return false
			end
		rescue Rex::AmbiguousArgumentError => info
			print_error(info.to_s)
		rescue NameError => info
			log_error("The supplied module name is ambiguous: #{$!}.")
		end

		return false if (mod == nil)

		# Enstack the command dispatcher for this module type
		dispatcher = nil

		case mod.type
			when MODULE_ENCODER
				dispatcher = Encoder
			when MODULE_EXPLOIT
				dispatcher = Exploit
			when MODULE_NOP
				dispatcher = Nop
			when MODULE_PAYLOAD
				dispatcher = Payload
			when MODULE_AUX
				dispatcher = Auxiliary
			else
				print_error("Unsupported module type: #{mod.type}")
				return false
		end

		# If there's currently an active module, go back
		if (active_module)
			cmd_back()
		end

		if (dispatcher != nil)
			driver.enstack_dispatcher(dispatcher)
		end

		# Update the active module
		self.active_module = mod

		# If a datastore cache exists for this module, then load it up
		if @dscache[active_module.fullname]
			active_module.datastore.update(@dscache[active_module.fullname])
		end
						
		mod.init_ui(driver.input, driver.output)

		# Update the command prompt
		driver.update_prompt("#{mod.type}(#{mod.shortname}) ")
	end
	
	#
	# Tab completion for the use command
	#
	def cmd_use_tabs(str, words)
		res = []
		
		framework.modules.module_types.each do |mtyp|
			mset = framework.modules.module_names(mtyp)
			mset.each do |mref|
				res << mtyp + '/' + mref
			end
		end
		
		return res.sort
	end
	
	#
	# Returns the revision of the framework and console library
	#
	def cmd_version(*args)
		ver = "$Revision$"

		print_line("Framework: #{Msf::Framework::Version}.#{Msf::Framework::Revision.match(/ (.+?) \$/)[1]}")
		print_line("Console  : #{Msf::Framework::Version}.#{ver.match(/ (.+?) \$/)[1]}")

		return true
	end

	#
	# Provide tab completion for option values
	#
	def tab_complete_option(str, words)
		opt = words[1]
		res = []
		mod = active_module
		
		# With no active module, we have nothing to compare
		if (not mod)
			return res
		end
		
		# Well-known option names specific to exploits
		if (mod.exploit?)
			return option_values_payloads() if opt.upcase == 'PAYLOAD'
			return option_values_targets()  if opt.upcase == 'TARGET'
			return option_values_nops()     if opt.upcase == 'NOPS'
		end

		# Well-known option names specific to auxiliaries
		if (mod.auxiliary?)
			return option_values_actions() if opt.upcase == 'ACTION'
		end
		
		# The ENCODER option works for payloads and exploits
		if ((mod.exploit? or mod.payload?) and opt.upcase == 'ENCODER')
			return option_values_encoders()
		end
		
		# Is this option used by the active module?
		if (mod.options.include?(opt))
			res.concat(option_values_dispatch(mod.options[opt], str, words))
		end
		
		# How about the selected payload?
		if (mod.exploit? and mod.datastore['PAYLOAD'])
			p = framework.modules.create(mod.datastore['PAYLOAD'])
			if (p and p.options.include?(opt))
				res.concat(option_values_dispatch(p.options[opt], str, words))
			end
		end

		return res
	end
	
	#
	# Provide possible option values based on type
	#
	def option_values_dispatch(o, str, words)	

		res = []
		res << o.default.to_s if o.default

		case o.class.to_s
		
			when 'Msf::OptAddress'
				case o.name.upcase
					when 'RHOST'
						option_values_target_addrs().each do |addr|
							res << addr
						end
					when 'LHOST'
						res << Rex::Socket.source_address()
					else
				end
			
			when 'Msf::OptAddressRange'

				case str
					when /\/$/
						res << str+'32'
						res << str+'24'
						res << str+'16'
					when /\-$/
						res << str+str[0, str.length - 1]
					else
						option_values_target_addrs().each do |addr|
							res << addr+'/32'
							res << addr+'/24'
							res << addr+'/16'
						end
				end
			
			when 'Msf::OptPort'
				case o.name.upcase
					when 'RPORT'
					option_values_target_ports().each do |port|
						res << port
					end
				end 
				
				if (res.empty?)
					res << (rand(65534)+1).to_s
				end
				
			when 'Msf::OptEnum'
				o.enums.each do |val|
					res << val
				end
		end
		
		return res
	end
	
	#
	# Provide valid payload options for the current exploit
	#
	def option_values_payloads
	
		# Module caching for significant speed improvement
		if (not (@cache_active_module and @cache_active_module == active_module.refname))
			@cache_active_module = active_module.refname
			@cache_payloads = active_module.compatible_payloads.map { |refname, payload| refname }
		end
		
		@cache_payloads
	end
	
	#
	# Provide valid target options for the current exploit
	#
	def option_values_targets
		res = []
		if (active_module.targets)
			1.upto(active_module.targets.length) { |i| res << (i-1).to_s }
		end
		return res
	end	
	
	
	#
	# Provide valid action options for the current auxiliary module
	#
	def option_values_actions
		res = []
		if (active_module.actions)
			active_module.actions.each { |i| res << i.name }
		end
		return res
	end	
	
	#
	# Provide valid nops options for the current exploit
	#
	def option_values_nops
		framework.nops.map { |refname, mod| refname }
	end	
	
	#
	# Provide valid encoders options for the current exploit or payload
	#
	def option_values_encoders
		framework.encoders.map { |refname, mod| refname }
	end

	#
	# Provide the target addresses
	#
	def option_values_target_addrs
		res = [ ]
		res << Rex::Socket.source_address()
		return res if not framework.db.active
		
		# List only those hosts with matching open ports?
		mport = self.active_module.datastore['RPORT']
		if (mport)
			mport = mport.to_i
			hosts = {}
			framework.db.each_service do |service|
				if (service.port == mport)
					hosts[ service.host.address ] = true
				end
			end
			
			hosts.keys.each do |host|
				res << host
			end
			
		# List all hosts in the database
		else
			framework.db.each_host do |host|
				res << host.address
			end
		end
		
		return res
	end

	#
	# Provide the target ports
	#
	def option_values_target_ports
		res = [ ]
		return res if not framework.db.active
		return res if not self.active_module.datastore['RHOST']
		host = framework.db.has_host?(self.active_module.datastore['RHOST'])
		return res if not host

		framework.db.each_service do |service|
			if (service.host_id == host.id)
				res << service.port.to_s
			end
		end

		return res
	end
				
protected

	#
	# Module list enumeration
	#
	
	def show_encoders(regex = nil) # :nodoc:
		# If an active module has been selected and it's an exploit, get the
		# list of compatible encoders and display them
		if (active_module and active_module.exploit? == true)
			tbl = generate_module_table("Compatible encoders")
            
			active_module.compatible_encoders.each { |refname, encoder|
				name = encoder.new.name

				if not regex or
				   refname =~ regex or
				   name =~ regex
					tbl << [ refname, name ]
				end
			}

			print(tbl.to_s)
		else
			show_module_set("Encoders", framework.encoders, regex)
		end
	end
	
	def show_nops(regex = nil) # :nodoc:
		show_module_set("NOP Generators", framework.nops, regex)
	end

	def show_exploits(regex = nil) # :nodoc:
		show_module_set("Exploits", framework.exploits, regex)
	end

	def show_payloads(regex = nil) # :nodoc:
		# If an active module has been selected and it's an exploit, get the
		# list of compatible payloads and display them
		if (active_module and active_module.exploit? == true)
			tbl = generate_module_table("Compatible payloads")

			active_module.compatible_payloads.each { |refname, payload|
				name = payload.new.name

				if not regex or
				   refname =~ regex or
				   name =~ regex
					tbl << [ refname, name ]
				end
			}

			print(tbl.to_s)
		else
			show_module_set("Payloads", framework.payloads, regex)
		end
	end

	def show_auxiliary(regex = nil) # :nodoc:
		show_module_set("Auxiliary", framework.auxiliary, regex)
	end

	def show_options(mod) # :nodoc:
		mod_opt = Serializer::ReadableText.dump_options(mod, '   ')
		print("\nModule options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)
	
		# If it's an exploit and a payload is defined, create it and
		# display the payload's options
		if (mod.exploit? and mod.datastore['PAYLOAD'])
			p = framework.modules.create(mod.datastore['PAYLOAD'])

			if (!p)
				print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
				return
			end
			
			p.share_datastore(mod.datastore)

			if (p)
				p_opt = Serializer::ReadableText.dump_options(p, '   ') 
				print("\nPayload options (#{mod.datastore['PAYLOAD']}):\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
			end
		end

		# Print the selected target
		if (mod.exploit? and mod.target)
			mod_targ = Serializer::ReadableText.dump_exploit_target(mod, '   ')
			print("\nExploit target:\n\n#{mod_targ}\n") if (mod_targ and mod_targ.length > 0)
		end

		# Uncomment this line if u want target like msf2 format
		#print("\nTarget: #{mod.target.name}\n\n")
	end

	def show_targets(mod) # :nodoc:
		mod_targs = Serializer::ReadableText.dump_exploit_targets(mod, '   ')
		print("\nExploit targets:\n\n#{mod_targs}\n") if (mod_targs and mod_targs.length > 0)
	end

	def show_actions(mod) # :nodoc:
		mod_actions = Serializer::ReadableText.dump_auxiliary_actions(mod, '   ')
		print("\nAuxiliary actions:\n\n#{mod_actions}\n") if (mod_actions and mod_actions.length > 0)
	end
		
	def show_advanced_options(mod) # :nodoc:
		mod_opt = Serializer::ReadableText.dump_advanced_options(mod, '   ') 
		print("\nModule advanced options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

		# If it's an exploit and a payload is defined, create it and
		# display the payload's options
		if (mod.exploit? and mod.datastore['PAYLOAD'])
			p = framework.modules.create(mod.datastore['PAYLOAD'])

			if (!p)
				print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
				return
			end
			
			p.share_datastore(mod.datastore)

			if (p)
				p_opt = Serializer::ReadableText.dump_advanced_options(p, '   ') 
				print("\nPayload advanced options (#{mod.datastore['PAYLOAD']}):\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
			end
		end
	end

	def show_evasion_options(mod) # :nodoc:
		mod_opt = Serializer::ReadableText.dump_evasion_options(mod, '   ') 
		print("\nModule evasion options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

		# If it's an exploit and a payload is defined, create it and
		# display the payload's options
		if (mod.exploit? and mod.datastore['PAYLOAD'])
			p = framework.modules.create(mod.datastore['PAYLOAD'])

			if (!p)
				print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
				return
			end
			
			p.share_datastore(mod.datastore)

			if (p)
				p_opt = Serializer::ReadableText.dump_evasion_options(p, '   ') 
				print("\nPayload evasion options (#{mod.datastore['PAYLOAD']}):\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
			end
		end
	end
	
	def show_plugins # :nodoc:
		tbl = generate_module_table("Plugins")

		framework.plugins.each { |plugin|
			tbl << [ plugin.name, plugin.desc ]
		}

		print(tbl.to_s)
	end

	def show_module_set(type, module_set, regex = nil) # :nodoc:
		tbl = generate_module_table(type)

		module_set.each_module { |refname, mod|
			instance = mod.new

			if not regex or
			   refname =~ regex or
			   instance.name =~ regex
				tbl << [ refname, instance.name ]
			end
		}

		print(tbl.to_s)
	end

	def generate_module_table(type) # :nodoc:
		Table.new(
			Table::Style::Default,
			'Header'  => type,
			'Prefix'  => "\n",
			'Postfix' => "\n",
			'Columns' => 
				[
					'Name',
					'Description'
				],
			'ColProps' =>
				{
					'Name' =>
						{
							# Default max width to 25
							'MaxWidth' => 25
						}
				})
	end

end

end end end end
