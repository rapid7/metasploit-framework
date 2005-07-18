require 'rex/parser/arguments'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Core
# ----
#
# Core meterpreter client commands.
#
###
class Console::Core

	include Console::CommandDispatcher

	@@use_opts = Rex::Parser::Arguments.new(
		"-m" => [ true,  "The name of the module or modules to load (Ex: stdapi)." ],
		"-h" => [ false, "Help banner."                                            ])

	#
	# List of supported commands
	#
	def commands
		{
			"exit" => "Terminate the meterpreter session",
			"use"  => "Load a one or more meterpreter extensions",
			"quit" => "Terminate the meterpreter session",
		}
	end

	#
	# Terminates the meterpreter session
	#
	def cmd_exit(*args)
		shell.stop
	end

	alias cmd_quit cmd_exit

	#
	# Loads one or more meterpreter extensions
	#
	def cmd_use(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		modules = nil

		@@use_opts.parse(args) { |opt, idx, val|
			case opt
				when "-m"
					modules = val.split(/,\s?/)
				when "-h"
					print(
						"Usage: use [options]\n\n" +
						"Loads a meterpreter extension module or modules.\n" +
						@use_opts.usage)
					return true
			end
		}

		# Load each of the modules
		modules.each { |m|
			print("Loading extension #{m}...")

			begin
				client.core.use(m)
			rescue
				log_error("failure: #{$!}")
				next
			end

			print_line("success.")
		}

		return true
	end

end

end
end
end
end
