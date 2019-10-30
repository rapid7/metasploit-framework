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

require 'rex/proto/rmi/model/element'
require 'rex/proto/rmi/model/output_header'
require 'rex/proto/rmi/model/protocol_ack'
require 'rex/proto/rmi/model/continuation'
require 'rex/proto/rmi/model/unique_identifier'
require 'rex/proto/rmi/model/call_data'
require 'rex/proto/rmi/model/call'
require 'rex/proto/rmi/model/return_value'
require 'rex/proto/rmi/model/return_data'
require 'rex/proto/rmi/model/dgc_ack'
require 'rex/proto/rmi/model/ping'
require 'rex/proto/rmi/model/ping_ack'