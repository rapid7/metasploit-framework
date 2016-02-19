# -*- coding: binary -*-

require 'rex/proto/kademlia/message'

module Rex
module Proto
module Kademlia
  # Opcode for a PING response
  PONG = 0x61

  # A Kademlia pong message.
  class Pong < Message
    # @return [Integer] the source port from which the PING was received
    attr_reader :port

    def initialize(port = nil)
      super(PONG)
      @port = port
    end

    # Builds a pong from given data
    #
    # @param data [String] the data to decode
    # @return [Pong] the pong if the data is valid, nil otherwise
    def self.from_data(data)
      message = super(data)
      return if message.type != PONG
      return if message.body.size != 2
      Pong.new(message.body.unpack('v')[0])
    end

    # Get this Pong as a String
    #
    # @return [String] the string representation of this Pong
    def to_str
      super + [@port].pack('v')
    end
  end
end
end
end
