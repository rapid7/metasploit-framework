#!/usr/bin/ruby

require 'Rex/IO/StreamAbstraction'
require 'Rex/Post/Meterpreter/Channel'

module Rex
module Post
module Meterpreter

###
#
# Stream
# ------
#
# This class represents a channel that is streaming.  This means
# that sequential data is flowing in either one or both directions.
#
###
class Stream < Rex::Post::Meterpreter::Channel

	include Rex::IO::StreamAbstraction

	class <<self
		def cls
			return CHANNEL_CLASS_STREAM
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

		initialize_abstraction
	end

	##
	#
	# Remote I/O handlers
	#
	##

	def dio_write_handler(packet, data)
		rsock.write(data)

		return true;
	end

	def dio_close_handler(packet)
		rsock.close
		
		return super(packet)
	end

end

end; end; end
