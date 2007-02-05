module Msf
module Ui
module Gtk2
module Stream

class Console < MyGlade
	
	def initialize(session, buffer, pipe, input, output)
		super('console2')
		
		@textview.set_buffer(buffer)
		
		@buffer = buffer
		@session = session
		@pipe = pipe
		@input = input
		@output = output
		
		# Create a read subscriber
		@pipe.create_subscriber(@session.sid)
		
		@output.print_status("Session #{@session.sid} created, interacting")
		@output.print_line
		
		if @console2.run == Gtk::Dialog::RESPONSE_OK
			puts "ok"
			@console2.destroy
		end
		
		@session.init_ui(@input, @output)
		@session.interact
		update_access
		
		@console2.destroy
		
	end
	
	#
	# update access
	#
	def update_access
		last_access = Time.now
	end
	#
	# Signal for user entry
	#
	def on_cmd_entry_activate
		send_cmd(@cmd_entry.text)
	end
	
	#
	# Send command to bidirectionnal_pipe
	#
	def send_cmd(cmd)
		
		update_access
		
		# Puts cmd
		puts cmd
		@pipe.write_input(cmd)
		@pipe.read_subscriber(@session.sid)
		
		# Clear entry
		@cmd_entry.set_text("")
	end
end

end
end
end
end

