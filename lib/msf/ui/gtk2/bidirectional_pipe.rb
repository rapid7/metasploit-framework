module Msf
module Ui
module Gtk2

require 'msf/ui/gtk2/stream/output'
require 'rex/ui/text/output/buffer'
require 'rex/ui/text/input/buffer'


class BidirectionalPipe < Rex::IO::BidirectionalPipe

	def initialize(buffer)
		@buffer = buffer
		if (not @buffer.get_mark('end_mark')
			@buffer.create_mark('end_mark', @buffer.end_iter, false)
		end
					
		super()
	end
	
	def print_error(msg)
		@buffer.insert(@buffer.end_iter, '[-] ' + msg)
		print_line
		scroll_line
	end
	
	def print_line(msg = "")
		@buffer.insert(@buffer.end_iter, msg + "\n")
		scroll_line
	end
	
	def print_good(msg)
		@buffer.insert(@buffer.end_iter, '[+] ' + msg)
		print_line
		scroll_line
	end
	
	def print_status(msg)
		@buffer.insert(@buffer.end_iter, '[*] ' + msg)
		print_line
		scroll_line
	end
	
	def scroll_line
		@buffer.move_mark('end_mark', @buffer.end_iter)
		@textview.scroll_mark_onscreen(@buffer.get_mark('end_mark'))		
	end

protected

end

end
end
end
