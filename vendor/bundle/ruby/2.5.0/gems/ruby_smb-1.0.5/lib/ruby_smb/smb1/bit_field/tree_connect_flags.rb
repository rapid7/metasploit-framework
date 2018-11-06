module RubySMB
  module SMB1
    module BitField
      # The Flags bit-field for an SMB1 TreeConnect Request Packet
      # [2.2.4.7.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/cc246330.aspx)
      class TreeConnectFlags < BinData::Record
        endian  :little
        bit4    :reserved,              label: 'Reserved Space',             initial_value: 0
        bit1    :extended_response,     label: 'Extended Response',          initial_value: 1
        bit1    :extended_signature,    label: 'Extended Signature',         initial_value: 0
        bit1    :reserved2,             label: 'Reserved Space',             initial_value: 0
        bit1    :disconnect,            label: 'Disconnect Tree',            initial_value: 0
        bit4    :reserved3,             label: 'Reserved Space',             initial_value: 0
        bit4    :reserved4,             label: 'Reserved Space',             initial_value: 0
      end
    end
  end
end
