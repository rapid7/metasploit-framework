#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Channels/Pool'

module Rex
module Post
module Meterpreter
module Channels
module Pools

###
#
# File
# ----
#
# This class represents a channel that is associated with a file
# on the remote half of the meterpreter connection.
#
###
class File < Rex::Post::Meterpreter::Channels::Pool

TLV_TYPE_SEEK_OFFSET = TLV_META_TYPE_UINT | (TLV_TEMP + 0)
TLV_TYPE_SEEK_WHENCE = TLV_META_TYPE_UINT | (TLV_TEMP + 1)
TLV_TYPE_SEEK_POS    = TLV_META_TYPE_UINT | (TLV_TEMP + 2)

	##
	#
	# Constructor
	#
	##

	# Initializes the file channel instance
	def initialize(client, cid, type, flags)
		super(client, cid, type, flags)
	end

	# Seeks to a different location in the file
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

		request = Packet.create_request('stdapi_fs_file_seek')

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

	# Gets the current position of the file pointer
	def tell
		request = Packet.create_request('stdapi_fs_file_tell')
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

end

end; end; end; end; end
