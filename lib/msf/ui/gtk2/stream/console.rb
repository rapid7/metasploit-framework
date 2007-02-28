module Msf
module Ui
module Gtk2
module Stream

class Console < MyGlade

	require 'rex/io/bidirectional_pipe'
	
	ID_SESSION, PEER, PAYLOAD, O_SESSION, O_BUFFER = *(0..5).to_a
	
	def initialize(iter)

		# Style
		console_style = File.join(driver.resource_directory, 'style', 'console.rc')
		Gtk::RC.parse(console_style)

		super('console2')
		
		@session = iter[O_SESSION]
		@buffer = iter[O_BUFFER]
		
		@textview.set_buffer(@buffer)
		@textview.editable = false
		@textview.set_cursor_visible(false)
		@buffer.create_mark('end_mark', @buffer.end_iter, false)
		
		# Give focus to Gtk::Entry
		@cmd_entry.can_focus = true
		@cmd_entry.grab_focus()
		
		# Create the pipe interface
		@pipe = Rex::IO::BidirectionalPipe.new
			
		# Start the session interaction
		@t_run = Thread.new do 
			@session.interact(@pipe, @pipe)
		end
		
		# Create a subscriber with a callback for the UI
		@sid = @pipe.create_subscriber_proc() do |data|
			@buffer.insert(@buffer.end_iter, Rex::Text.to_utf8(data))
			@buffer.move_mark('end_mark', @buffer.end_iter)
			@textview.scroll_mark_onscreen(@buffer.get_mark('end_mark'))				
		end
 
		# Run the console interface
		res = @console2.run
		
		# Kill the interaction thread
		@t_run.kill
		
		# Close the pipes
		@pipe.close
		
		# Determine how we were closed
		case res
		when Gtk::Dialog::RESPONSE_CLOSE
			close_console
		else
		end
	
		
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
		
		# Write the command plus a newline to the input
		@pipe.write_input(cmd + "\n")

		# Clear the text entry
		@cmd_entry.set_text("")
	end
	
	#
	# Just close the console, not kill !
	#
	def close_console
		@console2.destroy
	end
end



class GtkConsolePipe < Rex::IO::BidirectionalPipe


	attr_accessor :input
	attr_accessor :output
	attr_accessor :prompt
	attr_accessor :buffer
	attr_accessor :tree
	
	def initialize(buffer)
		self.buffer = buffer
		super()
	end
	
	def eof?
		self.pipe_input.eof?
	end

	def intrinsic_shell?
		true
	end

	def supports_readline
		false
	end
	
	def _print_prompt
	end
	
	def pgets
		self.pipe_input.gets
	end

	def print_line(msg = "")
		print(msg + "\n")
	end
	
	def print(msg = "")
		self.buffer.insert(self.buffer.end_iter, Time.now.strftime("%H:%m:%S") + " " + Rex::Text.to_utf8(msg))
	end	
	
end
	


end
end
end
end

