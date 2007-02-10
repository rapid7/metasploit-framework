module Msf
module Ui
module Gtk2

require 'msf/ui/gtk2/stream/output'
require 'rex/ui/text/output/buffer'
require 'rex/ui/text/input/buffer'

class BidirectionalPipe < Rex:IO::BidirectionalPipe

	def initialize(buffer)
		@buffer = buffer
		super()
	end
	
	def print_error(msg)
		@buffer.insert_at_cursor('[-] ' + msg)
		print_line
	end
	
	def print_line(msg = "")
		@buffer.insert_at_cursor(msg + "\n")
	end
	
	def print_good(msg)
		@buffer.insert_at_cursor('[+] ' + msg)
		print_line
	end
	
	def print_status(msg)
		@buffer.insert_at_cursor('[*] ' + msg)
		print_line
	end

protected

end

end
end
end
