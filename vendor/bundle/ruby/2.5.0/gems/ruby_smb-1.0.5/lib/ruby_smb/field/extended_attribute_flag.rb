module RubySMB
  module Field
    # Representation of the ExtendedAttributeFlag bit-field as defined in
    # [2.2.1.2.2 SMB_FEA](https://msdn.microsoft.com/en-us/library/ee915515.aspx)
    class ExtendedAttributeFlag < BinData::Record
      bit1  :file_need_ea,  label: 'EA Required'
      bit7  :reserved,      label: 'Reserved Space'
    end
  end
end
