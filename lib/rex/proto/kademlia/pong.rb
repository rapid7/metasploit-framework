# -*- coding: binary -*-

require 'rex/proto/kademlia/message'

module Rex
module Proto
module Kademlia
  # Opcode for a PING response
  PONG = 0x61

  # A Kademlia pong message.
  class Pong < Message
    # the source port from which the PING was received
    attr_reader :port

    def initialize(port = nil)
      super(PONG)
      @port = port
    end

    def self.from_data(data)
      message = super(data)
      return if message.type != PONG
      return if message.body.size != 2
      Pong.new(message.body.unpack('v')[0])
    end

    def to_str
      super + [@port].pack('v')
    end
  end
end
end
end
