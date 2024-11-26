# -*- coding: binary -*-

require 'bindata'

module Rex
  module Proto
    module IPMI
      class Open_Session_Reply < BinData::Record
        endian  :little
        uint8   :rmcp_version                     ,label: "RMCP Version"
        uint8   :rmcp_padding                     ,label: "RMCP Padding"
        uint8   :rmcp_sequence                    ,label: "RMCP Sequence"
        bit1    :rmcp_mtype                       ,label: "RMCP Message Type"
        bit7    :rmcp_class                       ,label: "RMCP Message Class"

        uint8   :session_auth_type                ,label: "Authentication Type"

        bit1    :session_payload_encrypted        ,label: "Session Payload Encr"
        bit1    :session_payload_authenticated    ,label: "Session Payload Auth"
        bit6    :session_payload_type             ,label: "Session Payload Type"

        uint32   :session_id                      ,label: "Session ID"
        uint32   :session_sequence                ,label: "Session Sequence Number"
        uint16   :message_length                  ,label: "Message Length"

        uint8    :ignored1                        ,label: "Ignored"
        uint8    :error_code                      ,label: "RMCP Error Code"
        uint16   :ignored2                        ,label: "Ignored"
        rest     :data                            ,label: "Session Info"
      end

      class Session_Data < BinData::Record
        endian   :little
        string   :console_session_id, length: 4   ,label: "Console Session ID"
        string   :bmc_session_id, length: 4       ,label: "BMC Session ID"
      end
    end
  end
end
