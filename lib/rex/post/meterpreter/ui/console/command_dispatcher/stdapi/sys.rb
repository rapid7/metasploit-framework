require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Sys
# ---
#
# The system level portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Sys

	Klass = Console::CommandDispatcher::Stdapi::Sys

	include Console::CommandDispatcher

	@@execute_opts = Rex::Parser::Arguments.new(
		"-a" => [ true,  "The arguments to pass to the command."        ],
		"-c" => [ false, "Channelized I/O (required for interaction)."  ],
		"-f" => [ true,  "The executable command to run."               ],
		"-h" => [ false, "Help menu."                                   ],
		"-H" => [ false, "Create the process hidden from view."         ],
		"-i" => [ false, "Interact with the process after creating it." ])

	#
	# List of supported commands
	#
	def commands
		{
			"execute" => "Execute a command",
			"getpid"  => "Get the current process identifier",
			"getuid"  => "Get the user that the server is running as",
			"kill"    => "Terminate a process",
			"ps"      => "List running processes",
			"sysinfo" => "Gets information about the remote system, such as OS",
		}
	end

	#
	# Name for this dispatcher
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

		interact    = false
		channelized = nil
		hidden      = nil
		cmd_args    = nil
		cmd_exec    = nil

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
				when "-h"
					print(
						"Usage: execute -f file [options]\n\n" +
						"Executes a command on the remote machine.\n" +
						@@execute_opts.usage)
					return true
				when "-i"
					channelized = true
					interact = true
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
			'Hidden'      => hidden)

		print_line("Process #{p.pid} created.")
		print_line("Channel #{p.channel.cid} created.") if (p.channel)

		if (interact and p.channel)
			shell.interact_with_channel(p.channel)	
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
	# Kills one or more processes.
	#
	def cmd_kill(*args)
		if (args.length == 0)
			print(
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
			'Indent'  => 4,
			'Columns' =>
				[
					"PID",
					"Name",
					"Path",
				])

		processes.each { |ent|
			tbl << [ ent['pid'].to_s, ent['name'], ent['path'] ]
		}

		if (processes.length == 0)
			print_line("No running processes were found.")
		else
			print("\n" + tbl.to_s + "\n")
		end

		return true
	end

	#
	# Displays information about the remote system.
	#
	def cmd_sysinfo(*args)
		info = client.sys.config.sysinfo

		print_line("Computer: " + info['Computer'])
		print_line("OS      : " + info['OS'])

		return true
	end

end

end
end
end
end
