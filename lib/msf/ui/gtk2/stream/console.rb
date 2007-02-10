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
		@input = input
		@output = output
		@pipe = pipe
		
		# Create a read subscriber
		@pipe.create_subscriber(@session.sid)
		
		@output.print_status("Session #{@session.sid} created, interacting")
		@output.print_line("\n")
		
		@session.init_ui(@input, @output)
		Thread.new{@session.interact}
		
		if @console2.run == Gtk::Dialog::RESPONSE_OK
			puts "ok"
			@console2.destroy
		end
		

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
		@input.put(cmd)
		@pipe.read_subscriber(@session.sid)
		
		# Clear entry
		@cmd_entry.set_text("")
	end
end

require 'rex/io/bidirectional_pipe'
class GtkConsolePipe < Rex::IO::BidirectionalPipe
	
	attr_accessor :input
	attr_accessor :output
	attr_accessor :prompt
	attr_accessor :killed
	
	def initialize(buffer)
		@buffer = buffer
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
		@buffer.insert_at_cursor(msg + "\n")
	end
end
	


end
end
end
end

