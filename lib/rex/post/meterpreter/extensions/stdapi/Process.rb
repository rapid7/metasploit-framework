#!/usr/bin/ruby

require 'Rex/Post/Process'
require 'Rex/Post/Meterpreter/Packet'
require 'Rex/Post/Meterpreter/Client'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

class Process < Rex::Post::Process

	class <<self
		attr_accessor :client
	end

	def Process.getpid
		request = Packet.create_request('stdapi_process_getpid')

		response = client.send_request(request)

		tlv = response.get_tlv(TLV_TYPE_PID)

		if (tlv != nil)
			return tlv.value
		else
			return 0
		end
	end

end

end; end; end; end; end
