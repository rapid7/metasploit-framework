# -*- coding: binary -*-

require 'rex/proto/kademlia/message'

module Rex
module Proto
module Kademlia
  # Opcode for a PING request
  PING = 0x60

  # A Kademlia ping message.
  class Ping < Message
    def initialize
      super(PING)
    end
  end
end
end
end
