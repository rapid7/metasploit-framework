# -*- coding: binary -*-

module Rex
module Proto
##
#
# Minimal support for the newer Kademlia protocol, referred to here and often
# elsewhere as Kademlia2.  It is unclear how this differs from the old protocol.
#
# Protocol details are hard to come by because most documentation is academic
# in nature and glosses over the low-level network details.  The best
# documents I found on the protocol are:
#
# http://gbmaster.wordpress.com/2013/05/05/botnets-surrounding-us-an-initial-focus-on-kad/
# http://gbmaster.wordpress.com/2013/06/16/botnets-surrounding-us-sending-kademlia2_bootstrap_req-kademlia2_hello_req-and-their-strict-cousins/
# http://gbmaster.wordpress.com/2013/11/23/botnets-surrounding-us-performing-requests-sending-out-kademlia2_req-and-asking-contact-where-art-thou/
#
##
module Kademlia
  # A simple Kademlia message
  class Message
    # The header that non-compressed Kad messages use
    STANDARD_PACKET = 0xE4
    # The header that compressed Kad messages use, which is currently unsupported
    COMPRESSED_PACKET = 0xE5

    # @return [Integer] the message type
    attr_reader :type
    # @return [String] the message body
    attr_reader :body

    # Construct a new Message from the provided type and body
    #
    # @param type [String] the message type
    # @param body [String] the message body
    def initialize(type, body = '')
      @type = type
      @body = body
    end

    # Construct a new Message from the provided data
    #
    # @param data [String] the data to interpret as a Kademlia message
    # @return [Message] the message if valid, nil otherwise
    def self.from_data(data)
      return if data.length < 2
      header, type = data.unpack('CC')
      if header == COMPRESSED_PACKET
        fail NotImplementedError, "Unable to handle #{data.length}-byte compressed Kademlia message"
      end
      return if header != STANDARD_PACKET
      Message.new(type, data[2, data.length])
    end

    # Get this Message as a String
    #
    # @return [String] the string representation of this Message
    def to_str
      [STANDARD_PACKET, @type].pack('CC') + @body
    end

    # Compares this Message and another Message for equality
    #
    # @param other [Message] the Message to compare
    # @return [Boolean] true iff the two messages have equal types and bodies, false otherwise
    def ==(other)
      type == other.type && body == other.body
    end
  end
end
end
end
