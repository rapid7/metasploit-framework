module RubySMB
  module SMB2
    module BitField
      # Represents a Security Mode BitField as defined by
      # [2.2.3 SMB2 NEGOTIATE Request](https://msdn.microsoft.com/en-us/library/cc246543.aspx)
      class Smb2SecurityModeSingle < BinData::Record
        endian :little
        bit6    :reserved,          label: 'Reserved'
        bit1    :signing_required,  label: 'Signing Required'
        bit1    :signing_enabled,   label: 'Signing Enabled'
      end
    end
  end
end
