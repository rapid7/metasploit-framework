module Rex
module Proto
module DCERPC
class Client

require 'rex/proto/dcerpc/uuid'
require 'rex/proto/dcerpc/response'
require 'rex/text'

	# Process a DCERPC response packet from a socket
	def self.read_response (socket) 

		begin
			head = socket.timed_read(10, 5)
		rescue Timeout::Error
			# puts "Error: #{ $! }"
		end
		
		if (! head or head.length() != 10)
			return
		end
	
		resp = Rex::Proto::DCERPC::Response.new(head)
		
		if (! resp.frag_len)
			return resp
		end

		begin
			body = socket.timed_read(resp.frag_len - 10, 10)
		rescue Timeout::Error
			# puts "Error: #{ $! }"
		end
		
		if (body.nil? or body.length() != resp.frag_len - 10)
			return resp
		end

		resp.parse(body)
		return resp
	end
	
end
end
end
end
