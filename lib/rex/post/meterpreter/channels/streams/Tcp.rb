#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Channels/Stream'

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
		return Channel.create(client, 'net_stream_tcp',
			self, CHANNEL_FLAG_SYNCHRONOUS,
			[
				{ 'type' => 

			]
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
