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

	def wdigest()
		request = Packet.create_request('boiler')#'mimikatz_wdigest')
		response = client.send_request(request)
	end	

end

end; end; end; end; end
