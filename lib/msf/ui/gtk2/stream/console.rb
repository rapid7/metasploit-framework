module Msf
module Ui
module Gtk2
module Stream

class Console < MyGlade

	require 'rex/io/bidirectional_pipe'
	
	def initialize(session)
		super('console2')

		@buffer = Gtk::TextBuffer.new
		@textview.set_buffer(@buffer)
		@textview.editable = false
		@textview.set_cursor_visible(false)
		@buffer.create_mark('end_mark', @buffer.end_iter, false)

		@session = session
		
		# Create the pipe interface
		@pipe = Rex::IO::BidirectionalPipe.new
		
		# Initialize the session
		@session.init_ui(@pipe, @pipe)
		
		# Start the session interaction
		@t_run = Thread.new do 
			@session.interact()
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
		
		# Reset the session UI handles
		@session.reset_ui
		
		# Close the pipes
		@pipe.close
		
		# Determine how we were closed
		case res
		when Gtk::Dialog::RESPONSE_OK
			$stderr.puts "ok"
		else
		end
	
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
		
		# Write the command plus a newline to the input
		@pipe.write_input(cmd + "\n")

		# Clear the text entry
		@cmd_entry.set_text("")
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

