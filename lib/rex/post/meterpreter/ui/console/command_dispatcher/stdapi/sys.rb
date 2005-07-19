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
			"ps"      => "List running processes",
			"execute" => "Execute a command",
			"kill"    => "Terminate a process",
			"getpid"  => "Get the current process identifier",
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
	end

	#
	# Kills one or more processes.
	#
	def cmd_kill(*args)
	end

	#
	# Lists running processes
	#
	def cmd_ps(*args)
	end

end

end
end
end
end
