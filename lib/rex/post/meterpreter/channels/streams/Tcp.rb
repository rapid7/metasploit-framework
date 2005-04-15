#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Channels/Stream'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Tlv'

module Rex
module Post
module Meterpreter
module Channels

###
#
# Tcp
# ---
#
# The TCP class wrappers a stream-based meterpreter channel.
#
###
class Tcp < Rex::Post::Meterpreter::Channels::Stream

	##
	#
	# Factory
	#
	##

	def Tcp.open(client, host, port)
		return Channel.create(client, 'stdapi_net_tcp_client',
			self, CHANNEL_FLAG_SYNCHRONOUS,
			[
				{ 
					'type'  => TLV_TYPE_HOST_NAME, 
					'value' => host
				},
				{
					'type'  => TLV_TYPE_PORT,
					'value' => port
				}
			])
	end

	##
	#
	# Constructor
	#
	##

	# Passes the initialization information up to the base class
	def initialize(client, cid, type, flags)
		super(client, cid, type, flags)
	end

end

end; end; end; end
