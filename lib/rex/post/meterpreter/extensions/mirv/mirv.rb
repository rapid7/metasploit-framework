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
							puts "[DD] Checking if payload has loop()"
							#print "PAYLOAD: '#{payload}'"
							if payload.index("function loop()")==nil then 
								
								payload="function loop()\n"+payload+"\nend\n"
								print "Payload did not contain loop(), new payload is:\n#{payload}"
								
							end
							puts "[DD] Crafting packets"
							request = Packet.create_request('mirv_exec_lua')
							request.add_tlv(TLV_TYPE_LUA_CODE, payload)
							request.add_tlv(TLV_TYPE_MIRV_NEWTHREAD,inthread)
							response = client.send_request(request)
							puts "[DD] Send packets to client"
							#print response
							#print(response) # DEBUG
							if (inthread) then
								thread_id=response.get_tlv_value(TLV_TYPE_MIRV_RET_THREADID)
								message=response.get_tlv_value(TLV_TYPE_MIRV_LUA_RETMSG)	
								return "Thread ID: #{thread_id}, #{message}"
							else
								return response.get_tlv_value(TLV_TYPE_MIRV_LUA_RETMSG)	
							end
							puts "[DD] Done!"
						end
						
						def mirv_thread_stop(threadid)
							request = Packet.create_request('mirv_thread_stop')
							request.add_tlv(TLV_TYPE_MIRV_RET_THREADID,threadid)
							response = client.send_request(request)
							return response
						end
						
						def mirv_thread_list
							request = Packet.create_request('mirv_thread_list')		
							response = client.send_request(request)
							threads  = []
							group=response.get_tlv(TLV_TYPE_MIRV_THREADLIST)
							
							group.each(TLV_TYPE_MIRV_THREADRECORD) { |t|
								threads << t.value
							}
							return threads
						end
						
					end
					
				end 
			end 
		end 
	end 
end