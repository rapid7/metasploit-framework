module Rex
module Proto
module DCERPC
class Client

require 'rex/proto/dcerpc/uuid'
require 'rex/proto/dcerpc/response'
require 'rex/text'

	# Process a DCERPC response packet from a socket
	def self.read_response (socket, timeout=5) 

		data = socket.get_once(-1, timeout)

		# We need at least 10 bytes to find the FragLen
		if (! data or data.length() < 10)
			return
		end
	
		# Pass the first 10 bytes to the constructor
		resp = Rex::Proto::DCERPC::Response.new(data.slice!(0, 10))
		
		# Something went wrong in the parser...
		if (! resp.frag_len)
			return resp
		end

		# Do we need to read more data?
		if (resp.frag_len > (data.length + 10))
			begin
				data << socket.timed_read(resp.frag_len - data.length - 10, timeout)
			rescue Timeout::Error
			end
		end

		# Still missing some data...
		if (data.length() != resp.frag_len - 10)
			$stderr.puts "Truncated DCERPC response :-("
			return resp
		end

		resp.parse(data)
		return resp
	end
	
end
end
end
end
