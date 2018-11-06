module RubySMB
  module Field
    # Class representing an SMB Get Extended Attribute structure as defined in
    # [2.2.1.2.1 SMB_GEA](https://msdn.microsoft.com/en-us/library/ee442131.aspx?f=255&MSPPError=-2147217396)
    class SmbGea < BinData::Record
      endian :little
      uint8   :attribute_name_length, label: 'Attribute Name Length', initial_value: -> { attribute_name.do_num_bytes }
      string  :attribute_name,        label: 'Attribute Name'
      uint8   :null_pad,              label: 'Null-Padding', initial_value: 0x00
    end
  end
end
