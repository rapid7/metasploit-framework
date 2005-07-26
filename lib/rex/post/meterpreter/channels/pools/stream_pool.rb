#!/usr/bin/ruby

require 'rex/post/meterpreter/channels/pool'
require 'rex/post/meterpreter/extensions/stdapi/tlv'

module Rex
module Post
module Meterpreter
module Channels
module Pools

###
#
# StreamPool
# ----------
#
# This class represents a channel that is associated with a 
# streaming pool that has no definite end-point.  While this
# may seem a paradox given the stream class of channels, it's
# in fact dinstinct because streams automatically forward
# traffic between the two ends of the channel whereas
# stream pools are always requested data in a single direction.
#
###
class StreamPool < Rex::Post::Meterpreter::Channels::Pool

	include Rex::IO::StreamAbstraction

	##
	#
	# Constructor
	#
	##

	# Initializes the file channel instance
	def initialize(client, cid, type, flags)
		super(client, cid, type, flags)

		initialize_abstraction
	end

	#
	# Streaming pools don't support tell, seek, or eof.
	#

	def tell
		throw NotImplementedError
	end

	def seek
		throw NotImplementedError
	end

	def eof
		return false
	end

	def dio_write_handler(packet, data)
		rsock.write(data)

		return true
	end

	def dio_close_handler(packet)
		rsock.close
		
		return super(packet)
	end

	def cleanup
		super

		cleanup_abstraction
	end

end

end; end; end; end; end
