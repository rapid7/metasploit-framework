#!/usr/bin/env ruby

require 'rex/post/meterpreter/extensions/sample/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Sample

###
#
# This is a sample meterpreter extension
#
###
class Sample < Extension


	def initialize(client)
		super(client, 'sample')

		client.register_extension_aliases(
			[
				{ 
					'name' => 'sample',
					'ext'  => self
				},
			])
	end

	def sample_ping(payload)
		request = Packet.create_request('sample_ping')
		request.add_tlv(TLV_TYPE_SAMPLE_PING, payload)
		response = client.send_request(request)
		#print "Pong value is:", TLV_TYPE_SAMPLE_PONG;
		return response.get_tlv_value(TLV_TYPE_SAMPLE_PONG);		
	end
	

end

end; end; end; end; end