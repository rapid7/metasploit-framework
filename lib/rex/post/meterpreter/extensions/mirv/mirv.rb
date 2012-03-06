#!/usr/bin/env ruby

require 'rex/post/meterpreter/extensions/Mirv/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Mirv

###
#
# This is a Mirv meterpreter extension
#
###
class Mirv < Extension


	def initialize(client)
		super(client, 'Mirv')

		client.register_extension_aliases(
			[
				{ 
					'name' => 'Mirv',
					'ext'  => self
				},
			])
	end

	def mirv_luado(payload,inthread=false)
		print "PAYLOAD: '#{payload}'
		if payload.start_with? "@" then
			payload=IO::File.new(payload,"r").read
		end
		request = Packet.create_request('mirv_exec_lua')
		request.add_tlv(TLV_TYPE_LUA_CODE, payload)
		request.add_tlv(TLV_TYPE_MIRV_NEWTHREAD,inthread)
		response = client.send_request(request)
		print response
		#print(response) # DEBUG
		if (inthread) then
		
			return response.get_tlv_value(TLV_TYPE_MIRV_RET_THREADID)
		else
			return response.get_tlv_value(TLV_TYPE_MIRV_LUA_RETMSG)	
		end
	end
	

end

end; end; end; end; end