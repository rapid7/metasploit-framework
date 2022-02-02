# -*- coding: binary -*-

require 'bindata'

module Rex
  module Proto
    module IPMI
      class RAKP2 < BinData::Record
        endian  :little
        uint8   :rmcp_version                   ,label: "RMCP Version"
        uint8   :rmcp_padding                   ,label: "RMCP Padding"
        uint8   :rmcp_sequence                  ,label: "RMCP Sequence"
        bit1    :rmcp_mtype                     ,label: "RMCP Message Type"
        bit7    :rmcp_class                     ,label: "RMCP Message Class"

        uint8   :session_auth_type              ,label: "Authentication Type"

        bit1    :session_payload_encrypted      ,label: "Session Payload Encrypted"
        bit1    :session_payload_authenticated  ,label: "Session Payload Authenticated"
        bit6    :session_payload_type           ,label: "Session Payload Type"

        uint32  :session_id                     ,label: "Session ID"
        uint32  :session_sequence               ,label: "Session Sequence Number"
        uint16  :message_length                 ,label: "Message Length"
        uint8   :ignored1                       ,label: "Ignored"
        uint8   :error_code                     ,label: "RMCP Error Code"
        uint16  :ignored2                       ,label: "Ignored"
        rest    :data                           ,label: "RAKP2 Data"
      end

      class RAKP2_Data < BinData::Record
        endian  :little
        string  :console_session_id, length: 4  ,label: "Console Session ID"
        string  :bmc_random_id, length: 16      ,label: "BMC Random ID"
        string  :bmc_guid, length: 16           ,label: "RAKP2 Hash 2 (nulls)"
        string  :hmac_sha1, length: 20          ,label: "HMAC_SHA1 Output"
      end
    end
  end
end
