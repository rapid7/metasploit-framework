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

	# Checks eof
	def eof
		request = Packet.create_request('core_channel_eof')

		request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)

		begin
			response = self.client.send_request(request)
		rescue
			return true
		end

		if (response.has_tlv?(TLV_TYPE_BOOL))
			return response.get_tlv_value(TLV_TYPE_BOOL)
		end

		return false
	end

	# Wraps the read operation to raise end-of-file as necessary
	def read(length = nil)
		begin
			data = super(length)
		rescue
			data = nil
		end

		if (((data == nil) || (data.length == 0)) && 
		    (self.eof))
			raise EOFError
		end

		return data
	end

	# Seeks to a different location in the pool
	def seek(offset, whence = SEEK_SET)
		sane = 0

		# Just in case...
		case whence
			when ::IO::SEEK_SET 
				sane = 0
			when ::IO::SEEK_CUR 
				sane = 1
			when ::IO::SEEK_END 
				sane = 2
			else
				raise RuntimeError, "Invalid seek whence #{whence}.", caller
		end

		request = Packet.create_request('core_channel_seek')

		request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)
		request.add_tlv(TLV_TYPE_SEEK_OFFSET, offset)
		request.add_tlv(TLV_TYPE_SEEK_WHENCE, sane)

		begin
			response = self.client.send_request(request)
		rescue
			return -1
		end
				
		return tell
	end

	# Synonym for tell
	def pos
		return tell
	end

	# Gets the current position in the pool
	def tell
		request = Packet.create_request('core_channel_tell')
		pos     = -1

		request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)

		begin
			response = self.client.send_request(request)
		rescue
			return pos
		end

		# Set the return value to the position that we're at
		if (response.has_tlv?(TLV_TYPE_SEEK_POS))
			pos = response.get_tlv_value(TLV_TYPE_SEEK_POS)
		end
			
		return pos
	end

protected
	attr_accessor :_eof

end

end; end; end; end
