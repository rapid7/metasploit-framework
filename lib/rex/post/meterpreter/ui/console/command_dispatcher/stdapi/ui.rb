require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Ui
# --
#
# The user interface portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Ui

	Klass = Console::CommandDispatcher::Stdapi::Ui

	include Console::CommandDispatcher

	#
	# List of supported commands
	#
	def commands
		{
			"idletime" => "Returns the number of seconds the remote user has been idle",
			"uictl"    => "Control some of the user interface components"
		}
	end

	#
	# Name for this dispatcher
	#
	def name
		"Stdapi: User interface"
	end

	#
	# Executes a command with some options.
	#
	def cmd_idletime(*args)
		seconds = client.ui.idle_time

		mins    = seconds / 60
		hours   = mins    / 60
		days    = hours   / 24
		secs    = seconds % 60

		print_line(
			"User has been idle for" +
			(days  > 0 ? " #{days.to_s} days"  : '') +
			(hours > 0 ? " #{hours.to_s} hours" : '') +
			(mins  > 0 ? " #{mins.to_s} minutes"  : '') +
			(secs  > 0 ? " #{secs.to_s} seconds"  : '') +
			".")
		
		return true
	end

	#
	# Enables/disables user interface mice and keyboards on the remote machine.
	#
	def cmd_uictl(*args)
		if (args.length < 2)
			print_line(
				"Usage: uictl [enable/disable] [keyboard/mouse]")
			return true
		end

		case args[0]
			when 'enable'
				case args[1]
					when 'keyboard'
						print_line("Enabling keyboard...")
						client.ui.enable_keyboard
					when 'mouse'
						print_line("Enabling mouse...")
						client.ui.enable_mouse
					else
						print_error("Unsupported user interface device: #{args[1]}")
				end
			when 'disable'
				case args[1]
					when 'keyboard'
						print_line("Disabling keyboard...")
						client.ui.disable_keyboard
					when 'mouse'
						print_line("Disabling mouse...")
						client.ui.disable_mouse
					else
						print_error("Unsupported user interface device: #{args[1]}")
				end
			else
				print_error("Unsupported command: #{args[0]}")
		end

		return true
	end

end

end
end
end
end
