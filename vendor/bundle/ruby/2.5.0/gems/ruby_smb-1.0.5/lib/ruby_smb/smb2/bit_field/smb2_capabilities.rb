module RubySMB
  module SMB2
    module BitField
      # Represents a Capabilities BitField as defined by
      # [2.2.3 SMB2 NEGOTIATE Request](https://msdn.microsoft.com/en-us/library/cc246543.aspx)
      class Smb2Capabilities < BinData::Record
        endian  :little
        bit1    :reserved1,           label: 'Reserved'
        bit1    :encryption,          label: 'Encryption'
        bit1    :directory_leasing,   label: 'Directory Leasing'
        bit1    :persistent_handles,  label: 'Persistent Handles'
        bit1    :multi_channel,       label: 'Multi Channel'
        bit1    :large_mtu,           label: 'Large MTU'
        bit1    :leasing,             label: 'Leasing'
        bit1    :dfs,                 label: 'DFS'
        # byte border
        uint8   :reserved2,           label: 'Reserved'
        uint8   :reserved3,           label: 'Reserved'
        uint8   :reserved4,           label: 'Reserved'
      end
    end
  end
end
