#!/usr/bin/env ruby

require 'rex/post/meterpreter/inbound_packet_handler'

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

###
#
# The channel class represents a logical data pipe that exists between the
# client and the server.  The purpose and behavior of the channel depends on
# which type it is.  The three basic types of channels are streams, datagrams,
# and pools.  Streams are basically equivalent to a TCP connection.
# Bidirectional, connection-oriented streams.  Datagrams are basically
# equivalent to a UDP session.  Bidirectional, connectionless.  Pools are
# basically equivalent to a uni-directional connection, like a file handle.
# Pools denote channels that only have requests flowing in one direction.
#
###
class Channel

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

			dio = channel.dio_map(packet.method)

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

	#
	# Creates a logical channel between the client and the server 
	# based on a given type.
	#
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

		# FIXME: race condition where data could be sent to the channel
		#        before it's added to the list.

		# Create the channel instance
		channel  = klass.new(client, cid, type, flags)
	
		return channel
	end

	##
	#
	# Constructor
	#
	##

	#
	# Initializes the instance's attributes, such as client context,
	# class identifier, type, and flags.
	#
	def initialize(client, cid, type, flags)
		self.client = client
		self.cid    = cid
		self.type   = type
		self.flags  = flags

		# Add this instance to the list and shit
		if (cid and client)
			client.add_channel(self)
		end
	end

	##
	#
	# Channel interaction
	#
	##

	#
	# Wrapper around the low-level channel read operation.
	#
	def read(length = nil, addends = nil)
		return _read(length, addends)
	end

	#
	# Reads data from the remote half of the channel.
	#
	def _read(length = nil, addends = nil)
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

	#
	# Wrapper around the low-level write.
	#
	def write(buf, length = nil, addends = nil)
		return _write(buf, length, addends)
	end

	#
	# Writes data to the remote half of the channel.
	#
	def _write(buf, length = nil, addends = nil)
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

	#
	# Wrapper around the low-level close.
	#
	def close(addends = nil)
		return _close(addends)
	end

	#
	# Close the channel for future writes.
	#
	def close_write
		return _close
	end

	#
	# Close the channel for future reads.
	#
	def close_read
		return _close
	end

	#
	# Closes the channel.
	#
	def _close(addends = nil)
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

	#
	# Enables or disables interactive mode.
	#
	def interactive(tf = true, addends = nil)
		if (self.cid == nil)
			raise IOError, "Channel has been closed.", caller
		end

		request = Packet.create_request('core_channel_interact')

		# Populate the request
		request.add_tlv(TLV_TYPE_CHANNEL_ID, self.cid)
		request.add_tlv(TLV_TYPE_BOOL, tf)
		request.add_tlvs(addends)

		self.client.send_request(request)

		return true
	end

	##
	#
	# Direct I/O
	#
	##

	#
	# Handles dispatching I/O requests based on the request packet.
	# The default implementation does nothing with direct I/O requests.
	#
	def dio_handler(dio, packet)
		if (dio == CHANNEL_DIO_READ)
			length = packet.get_tlv_value(TLV_TYPE_LENGTH)

			return dio_read_handler(packet, length)
		elsif (dio == CHANNEL_DIO_WRITE)
			data = packet.get_tlv_value(TLV_TYPE_CHANNEL_DATA)

			return dio_write_handler(packet, data)
		elsif (dio == CHANNEL_DIO_CLOSE)
			return dio_close_handler(packet)
		end

		return false;
	end

	#
	# Stub read handler.
	#
	def dio_read_handler(packet, length)
		return false
	end

	#
	# Stub write handler.
	#
	def dio_write_handler(packet, data)
		return false
	end

	#
	# Stub close handler.
	#
	def dio_close_handler(packet)
		client.remove_channel(self.cid)

		# Trap IOErrors as parts of the channel may have already been closed
		begin
			self.cleanup
		rescue IOError
		end

		# No more channel action, foo.
		self.cid = nil

		return false
	end

	#
	# Maps packet request methods to DIO request identifiers on a
	# per-instance basis as other instances may add custom dio
	# handlers.
	#
	def dio_map(method)
		if (method == 'core_channel_read')
			return CHANNEL_DIO_READ
		elsif (method == 'core_channel_write')
			return CHANNEL_DIO_WRITE
		elsif (method == 'core_channel_close')
			return CHANNEL_DIO_CLOSE
		end

		return nil
	end

	##
	#
	# Conditionals
	#
	##

	#
	# Checks to see if a flag is set on the instance's flags attribute.
	#
	def flag?(flag)
		return ((self.flags & flag) == flag)
	end

	#
	# Returns whether or not the channel is operating synchronously.
	#
	def synchronous?
		return (self.flags & CHANNEL_FLAG_SYNCHRONOUS)
	end

	#
	# The unique channel identifier.
	#
	attr_reader   :cid
	#
	# The type of channel.
	#
	attr_reader   :type
	#
	# The class of channel (stream, datagram, pool).
	#
	attr_reader   :cls
	#
	# Any channel-specific flag, like synchronous IO.
	#
	attr_reader   :flags

protected

	attr_accessor :client # :nodoc:
	attr_writer   :cid, :type, :cls, :flags # :nodoc:

	#
	# Cleans up any lingering resources
	# 
	def cleanup
	end

end

end; end; end