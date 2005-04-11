#!/usr/bin/ruby

module Rex
module Post
module Meterpreter

class Channel

	@@channels = []

	## 
	#
	# Factory
	#
	##

=begin
	create(client, type, addends)

	Creates a logical channel between the client and the server 
	based on a given type.
=end
	def Channel.create(client, type = nil, 
			flags = CHANNEL_FLAG_SYNCHRONOUS, addends = nil)
		request = Packet.create_request('core_channel_open')

		# Set the type of channel that we're allocating
		if (type != nil)
			request.add_tlv(TLV_TYPE_CHANNEL_TYPE, type)
		end

		# Add flag information and addends
		request.add_tlv(TLV_TYPE_FLAGS, flags)
		request.add_tlvs(addends);

		# Transmit the request and wait for the response
		response   = client.send_request(request)
		cid = response.get_tlv(TLV_TYPE_CHANNEL_ID).value

		# Create the channel instance
		channel = Channel.new(client, cid, type, flags)
	
		# Insert the instance into the channel list
		if (channel != nil)
			@@channels << channel
		end

		return channel
	end

	##
	#
	# Constructor
	#
	##
	
	def initialize(client, cid, type, flags = 0)
		self.client = client
		self.cid    = cid
		self.type   = type
		self.flags  = flags
	end

	##
	#
	# Channel interaction
	#
	##

	def recv(length = nil, addends = nil)
		if (self.cid == nil)
			raise IOError, "Channel has been closed.", caller
		end

		request = Packet.create_request('core_channel_read')

		if (length == nil)
			length = 65536
		end

		request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)
		request.add_tlv(TLV_TYPE_LENGTH, length)
		request.add_tlvs(addends)

		response = self.client.send_request(request)

		# If the channel is in synchronous mode, the response should contain
		# data that was read from the remote side of the channel
		if (flag?(CHANNEL_FLAG_SYNCHRONOUS))
			data = response.get_tlv(TLV_TYPE_CHANNEL_DATA);

			if (data != nil)
				return data.value
			end
		else
			raise NotImplementedError, "Asynchronous channel mode is not implemented", caller
		end

		return nil
	end

	def send(buf, length = nil, addends = nil)
		if (self.cid == nil)
			raise IOError, "Channel has been closed.", caller
		end

		request = Packet.create_request('core_channel_write')

		# Truncation and celebration
		if ((length != nil) &&
		    (buf.length >= length))
			buf = buf[0..length]
		else
			length = buf.length
		end

		# Populate the request
		request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)
		request.add_tlv(TLV_TYPE_CHANNEL_DATA, buf)
		request.add_tlv(TLV_TYPE_LENGTH, length)
		request.add_tlvs(addends)

		response = self.client.send_request(request)
		written  = response.get_tlv(TLV_TYPE_LENGTH)

		return (written == nil) ? 0 : written.value
	end

	def close(addends = nil)
		if (self.cid == nil)
			raise IOError, "Channel has been closed.", caller
		end

		request = Packet.create_request('core_channel_close')

		# Populate the request
		request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)
		request.add_tlvs(addends)

		self.client.send_request(request)

		self.cid = nil

		return true
	end

	##
	#
	# Direct I/O
	#
	##

	def dio
		raise NotImplementedError, "dio not implemented", caller
	end


	##
	#
	# Conditionals
	#
	##

	def flag?(flag)
		return ((self.flags & flag) == flag)
	end

	attr_reader   :cid, :type, :flags
	attr_accessor :dio_handler

protected

	attr_accessor :client
	attr_writer   :cid, :type, :flags

end

end; end; end
