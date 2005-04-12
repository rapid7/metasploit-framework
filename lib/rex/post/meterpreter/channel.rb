#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/InboundPacketHandler'

module Rex
module Post
module Meterpreter

#
# The various types of channels
#
CHANNEL_CLASS_STREAM     = 1
CHANNEL_CLASS_DATAGRAM   = 2
CHANNEL_CLASS_POOL       = 3

#
# The various flags that can affect how the channel operates
#
#   CHANNEL_FLAG_SYNCHRONOUS
#      Specifies that I/O requests on the channel are blocking.
#
CHANNEL_FLAG_SYNCHRONOUS = (1 << 0)

#
# The core types of direct I/O requests
#
CHANNEL_DIO_READ         = 'read'
CHANNEL_DIO_WRITE        = 'write'
CHANNEL_DIO_CLOSE        = 'close'

class Channel

	# Maps packet request methods to DIO request identifiers on a
	# per-instance basis as other instances may add custom dio
	# handlers.
	@dio_map   = 
		{ 
			'core_channel_read'  => CHANNEL_DIO_READ,
			'core_channel_write' => CHANNEL_DIO_WRITE,
			'core_channel_close' => CHANNEL_DIO_CLOSE,
		}

	# Class modifications to support global channel message
	# dispatching without having to register a per-instance handler
	class <<self
		include Rex::Post::Meterpreter::InboundPacketHandler

		# Class request handler for all channels that dispatches requests
		# to the appropriate class instance's DIO handler
		def request_handler(client, packet)
			cid = packet.get_tlv_value(TLV_TYPE_CHANNEL_ID)

			# No channel identifier, then drop out 'n shit
			if (cid == nil)
				return false
			end

			channel = client.find_channel(cid)

			# Valid channel context?
			if (channel == nil)
				return false
			end
		
			dio = channel.dio_map[packet.method]

			# Supported DIO request?
			if (dio == nil)
				return false
			end

			# Call the channel's dio handler and return success or fail
			# based on what happens
			return channel.dio_handler(dio, packet)
		end
	end

	## 
	#
	# Factory
	#
	##

	# Creates a logical channel between the client and the server 
	# based on a given type.
	def Channel.create(client, type = nil, klass = nil, 
			flags = CHANNEL_FLAG_SYNCHRONOUS, addends = nil)
		request = Packet.create_request('core_channel_open')

		# Set the type of channel that we're allocating
		if (type != nil)
			request.add_tlv(TLV_TYPE_CHANNEL_TYPE, type)
		end

		# If no factory class was provided, use the default native class
		if (klass == nil)
			klass = self
		end

		request.add_tlv(TLV_TYPE_CHANNEL_CLASS, klass.cls)
		request.add_tlv(TLV_TYPE_FLAGS, flags)
		request.add_tlvs(addends);

		# Transmit the request and wait for the response
		response = client.send_request(request)
		cid      = response.get_tlv(TLV_TYPE_CHANNEL_ID).value

		# Create the channel instance
		channel  = klass.new(client, cid, type, flags)
	
		# Insert the instance into the channel hash
		if (channel != nil)
			client.add_channel(channel)
		end

		return channel
	end

	##
	#
	# Constructor
	#
	##

	# Initializes the instance's attributes, such as client context,
	# class identifier, type, and flags
	def initialize(client, cid, type, flags)
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

	# Reads data from the remote half of the channel
	def read(length = nil, addends = nil)
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

		begin
			response = self.client.send_request(request)
		rescue 
			return nil
		end

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

	# Writes data to the remote half of the channel
	def write(buf, length = nil, addends = nil)
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

	# Closes the channel
	def close(addends = nil)
		if (self.cid == nil)
			raise IOError, "Channel has been closed.", caller
		end

		request = Packet.create_request('core_channel_close')

		# Populate the request
		request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)
		request.add_tlvs(addends)

		self.client.send_request(request)

		# Disassociate this channel instance
		self.client.remove_channel(self.cid)

		self.cid = nil

		return true
	end

	##
	#
	# Direct I/O
	#
	##

	# Handles dispatching I/O requests based on the request packet.
	# The default implementation does nothing with direct I/O requests.
	def dio_handler(dio, packet)
		return nil
	end

	##
	#
	# Conditionals
	#
	##

	# Checks to see if a flag is set on the instance's flags attribute
	def flag?(flag)
		return ((self.flags & flag) == flag)
	end

	# Returns whether or not the channel is operating synchronously
	def synchronous?
		return (self.flags & CHANNEL_FLAG_SYNCHRONOUS)
	end

	attr_reader   :cid, :type, :cls, :flags

protected

	attr_accessor :client
	attr_writer   :cid, :type, :cls, :flags

end

end; end; end
