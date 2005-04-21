#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Channels/Stream'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net
module SocketSubsystem

###
#
# TcpClientChannel
# ----------------
#
# This class represents a logical TCP client connection
# that is established from the remote machine and tunnelled
# through the established meterpreter connection, similar to an
# SSH port forward.
#
###
class TcpClientChannel < Rex::Post::Meterpreter::Stream

	##
	#
	# Factory
	#
	##
	
	# Opens a TCP client channel using the supplied parameters
	def TcpClientChannel.open(client, params)
		return Channel.create(client, 'stdapi_net_tcp_client',
				self, CHANNEL_FLAG_SYNCHRONOUS,
				[
					{
						'type'  => TLV_TYPE_PEER_HOST,
						'value' => params.peerhost
					},
					{
						'type'  => TLV_TYPE_PEER_PORT,
						'value' => params.peerport
					},
					{
						'type'  => TLV_TYPE_LOCAL_HOST,
						'value' => params.localhost
					},
					{
						'type'  => TLV_TYPE_LOCAL_PORT,
						'value' => params.localport
					},
					{
						'type'  => TLV_TYPE_CONNECT_RETRIES,
						'value' => params.retries
					}
				])
	end

	##
	#
	# Constructor
	#
	##

	# Passes the channel initialization information up to the base class
	def initialize(client, cid, type, flags)
		super(client, cid, type, flags)
	end

end

end; end; end; end; end; end; end
