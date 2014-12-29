# -*- coding: binary -*-

require 'rex/proto/kademlia/message'

module Rex
module Proto
module Kademlia
  # Opcode for a BOOTSTRAP request
  BOOTSTRAP_REQUEST = 0x01

  # A Kademlia bootstrap request message
  class BootstrapRequest < Message
    def initialize
      super(BOOTSTRAP_REQUEST)
    end
  end
end
end
end
