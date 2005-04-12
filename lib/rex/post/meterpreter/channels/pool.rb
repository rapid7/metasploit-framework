#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Channel'

module Rex
module Post
module Meterpreter
module Channels

###
#
# Pool
# ----
#
# This class acts as a base class for all channels that are classified
# as 'pools'.  This means that only one side of the channel, typically
# the client half, acts on the other half of the channel.  Examples
# of pools come in the form of files where the remote side never sends
# any unrequested data.
#
# Another key distinction of Pools is that they, in general, support
# the DIO mode 'seek' which allows for changing the position, or offset,
# into the channel.
#
###
class Pool < Rex::Post::Meterpreter::Channel

	class <<self
		def cls
			return CHANNEL_CLASS_POOL
		end
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

	##
	#
	# Channel interaction
	#
	##

	# Stub for seeking to a different location on the remote half of the
	# channel
	def seek(offset, whence = SEEK_SET)
		raise NotImplementedError
	end

	# Stub for getting the current position on the remote half of the 
	# channel
	def tell
		raise NotImplementedError
	end

	# Synonym for tell
	def pos
		return tell
	end

end

end; end; end; end
