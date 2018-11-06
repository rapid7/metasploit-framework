module RubySMB
  module SMB2
    module BitField
      # Represents a Share Capabilities BitField as defined by
      # [2.2.10 SMB2 TREE_CONNECT Response](https://msdn.microsoft.com/en-us/library/cc246499.aspx)
      class ShareCapabilities < BinData::Record
        endian  :little
        bit1    :asymmetric,          label: 'Asymmetric'
        bit1    :cluster,             label: 'Cluster'
        bit1    :scaleout,            label: 'Scale Out'
        bit1    :continuous,          label: 'Continuous Availability'
        bit1    :dfs,                 label: 'DFS'
        bit3    :reserved2,           label: 'Reserved Space'
        # byte border
        uint8   :reserved3,           label: 'Reserved'
        uint8   :reserved4,           label: 'Reserved'
        uint8   :reserved5,           label: 'Reserved'
      end
    end
  end
end
