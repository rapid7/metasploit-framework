module RubySMB
  module SMB1
    module BitField
      # Represents a ShareAccess Bit-Field as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      class ShareAccess < BinData::Record
        endian :little
        bit5  :reserved,        label: 'Reserved Space'
        bit1  :share_delete,    label: 'Share Delete Access'
        bit1  :share_write,     label: 'Share Write Access'
        bit1  :share_read,      label: 'Share Read Access'
        # Byte Boundary
        bit8  :reserved2, label: 'Reserved Space'
        bit8  :reserved3, label: 'Reserved Space'
        bit8  :reserved4, label: 'Reserved Space'
      end
    end
  end
end
