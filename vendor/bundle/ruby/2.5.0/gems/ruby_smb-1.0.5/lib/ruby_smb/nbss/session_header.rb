module RubySMB
  module Nbss
    # Representation of the NetBIOS Session Service Header as defined in
    # [4.3.1 GENERAL FORMAT OF SESSION PACKETS](https://tools.ietf.org/html/rfc1002)
    class SessionHeader < BinData::Record
      endian :big

      uint8 :session_packet_type,  label: 'Session Packet Type'
      bit7  :flags,                label: 'Flags',              initial_value: 0
      bit17 :packet_length,        label: 'Packet Length'
    end
  end
end
