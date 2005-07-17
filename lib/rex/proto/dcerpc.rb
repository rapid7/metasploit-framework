#!/usr/bin/env ruby -w

##
#    Name: Rex::Proto::DCERPC
# Purpose: Provide DCERPC creation and processing routines
#  Author: H D Moore <hdm [at] metasploit.com>
# Version: $Revision$
##

module Rex
module Proto
class DCERPC

require 'rex/proto/dcerpc/uuid'
require 'rex/proto/dcerpc/response'
	
	def read_response (socket) 
		head = socket.timed_read(10, 5)
		if (! head or head.length() != 10)
			return
		end
		
		resp = Rex::Proto::DCERPC::Response.new(head)
		
		if (! resp.frag_len)
			return resp
		end
		
		body = socket.timed_read(resp.frag_len, 10)
		if (! body or body.length() != resp.frag_len) 
			return resp
		end
		
		resp.parse(body)
		return resp
	end

end
end
end

if $0 == __FILE__
	dcerpc = Rex::Proto::DCERPC.new()
	puts "[*] All DCERPC tests have passed :-)"	
end
