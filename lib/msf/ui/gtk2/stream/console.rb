module Msf
module Ui
module Gtk2
module Stream

class Console < MyGlade
	
	def initialize(session, buffer, pipe, input, output)
		super('console2')
		
		@textview.set_buffer(buffer)
		@textview.editable = false
		
		@buffer  = buffer
		@session = session
		@input   = input
		@output  = output
		@pipe    = pipe

		
		# Create a read subscriber
		@pipe.create_subscriber(@session.sid)
		
		@output.print_status("Session #{@session.sid} created, interacting")
		@output.print_line("\n")
		
		@session.init_ui(@input, @output)
		
		# One thread to interact
		@t_mon = Thread.new do
			@session.interact
		end
		
		# Another to monitor the output and update the UI
		@t_rdr = Thread.new do

			if (not @buffer.get_mark('end_mark'))
				@buffer.create_mark('end_mark', @buffer.end_iter, false)
			end
			
			while(true)
				data = @pipe.read_subscriber(@session.sid)
				if (data and data.length > 0)
					@buffer.insert(@buffer.end_iter, data)
					@buffer.move_mark('end_mark', @buffer.end_iter)
					@textview.scroll_mark_onscreen(@buffer.get_mark('end_mark'))	
				else
					select(nil, nil, nil, 0.10)
				end
				
			end
		end
		
				
		if @console2.run == Gtk::Dialog::RESPONSE_OK
			puts "ok"
			@console2.destroy
		end
		
		
		# Kill off the helper threads
		@t_rdr.kill
		@t_mon.kill

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
		
		# Write the command plus a newline to the input
		@input.put(cmd + "\n")

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

