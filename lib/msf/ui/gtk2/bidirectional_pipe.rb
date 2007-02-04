module Msf
module Ui
module Gtk2

require 'msf/ui/gtk2/output'
require 'rex/ui/text/output/buffer'
require 'rex/ui/text/input/buffer'

class BidirectionalPipe < Msf::Ui::Input

	def initialize(buffer)
		@buffer = buffer
		@subscribers_out = {}
		@pipe_input = Rex::Ui::Text::Input::Buffer.new
	end

	def pipe_input
		@pipe_input
	end

	def close
		@pipe_input.close
	end

	def create_subscriber(id)
		@subscribers_out[id] = Rex::Ui::Text::Output::Buffer.new
	end

	def remove_subscriber(id)
		@subscribers_out.delete(id)
	end

	def write_input(buf)
		@pipe_input.put(buf)
	end

	def read_subscriber(id)
		output = @subscribers_out[id]

		return '' if output.nil?

		buf = output.buf

		output.reset

		buf
	end

	def print(msg)
		@subscribers_out.each_pair { |id, buf|
			buf.print(msg)
		}
	end
	
	def print_error(msg)
		print_line('[-] ' + msg)
	end
	
	def print_line(msg)
		@buffer.insert_at_cursor(msg + "\n")
	end
	
	def print_good(msg)
		print_line('[+] ' + msg)
	end

	def flush
	end
	
	def print_status(msg)
		print_line('[*] ' + msg)
	end

protected

end

end
end
end
