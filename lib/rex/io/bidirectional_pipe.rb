module Rex
module IO

require 'rex/ui/text/output'
require 'rex/ui/text/output/buffer'
require 'rex/ui/text/input/buffer'

class BidirectionalPipe < Rex::Ui::Text::Input

	def initialize
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

protected

end

end
end
