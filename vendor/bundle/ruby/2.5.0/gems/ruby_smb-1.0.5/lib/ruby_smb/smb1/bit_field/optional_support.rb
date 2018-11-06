module RubySMB
  module SMB1
    module BitField
      # The OptionalSupport bit-field for an SMB1 TreeConnect Response Packet
      # [2.2.4.7.2 Server Response Extensions](https://msdn.microsoft.com/en-us/library/cc246331.aspx)
      class OptionalSupport < BinData::Record
        endian  :little
        bit2    :reserved,              label: 'Reserved Space',             initial_value: 0
        bit1    :extended_signature,    label: 'Extended Signature',         initial_value: 0
        bit1    :unique_filename,       label: 'Unique Filename',            initial_value: 0
        bit2    :csc_mask,              label: 'CSC Mask',                   initial_value: 0
        bit1    :dfs,                   label: 'DFS Share',                  initial_value: 0
        bit1    :search,                label: 'Exclusive Search Bits',      initial_value: 1
        bit8    :reserved2,             label: 'Reserved Space',             initial_value: 0
      end
    end
  end
end
