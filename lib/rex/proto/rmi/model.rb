# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        SIGNATURE              = 'JRMI'
        STREAM_PROTOCOL        = 0x4b
        SINGLE_OP_PROTOCOL     = 0x4c
        MULTIPLEX_PROTOCOL     = 0x4d
        CALL_MESSAGE           = 0x50
        PING_MESSAGE           = 0x52
        DGC_ACK_MESSAGE        = 0x54
        PROTOCOL_ACK           = 0x4e
        PROTOCOL_NOT_SUPPORTED = 0x4f
        RETURN_DATA            = 0x51
        PING_ACK               = 0x53
        RETURN_VALUE           = 1
        RETURN_EXCEPTION       = 2
      end
    end
  end
end
