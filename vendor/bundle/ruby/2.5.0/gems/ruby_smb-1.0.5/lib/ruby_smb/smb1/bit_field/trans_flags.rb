module RubySMB
  module SMB1
    module BitField
      # The Flags bit-field for Trans and Trans2 Request Packets as defined in
      # [2.2.4.33.1 Request](https://msdn.microsoft.com/en-us/library/ee441730.aspx) and
      # [2.2.4.46.1 Request](https://msdn.microsoft.com/en-us/library/ee442192.aspx)
      class TransFlags < BinData::Record
        endian  :little
        bit6    :reserved,              label: 'Reserved Space',             initial_value: 0
        bit1    :no_response,           label: 'Do Not reply',               initial_value: 0
        bit1    :disconnect,            label: 'Disconnect Tree',            initial_value: 0
        bit8    :reserved2,             label: 'Reserved Space',             initial_value: 0
      end
    end
  end
end
