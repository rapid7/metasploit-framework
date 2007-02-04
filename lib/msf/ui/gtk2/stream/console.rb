module Msf
module Ui
module Gtk2
module Stream

class Console < MyGlade
	
	def initialize(session, buffer, input, output)
		super('console2')
		
		@textview.set_buffer(buffer)
		
		@buffer = buffer
		@session = session
		@input = input
		@output = output
		
		@output.print_status("Session #{@session.sid} created, interacting")
		@output.print_line
		
		if @console2.run == Gtk::Dialog::RESPONSE_OK
			puts "ok"
			@console2.destroy
		end
		
		@session.init_ui(@input, @output)
		@session.interact
		@console2.destroy
		
	end
end

end
end
end
end

