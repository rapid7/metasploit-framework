module RubySMB
  module Field
    # Class representing an SMB File Extended Attribute as defined in
    # [2.2.1.2.2 SMB_FEA](https://msdn.microsoft.com/en-us/library/ee915515.aspx)
    class SmbFea < BinData::Record
      endian :little
      extended_attribute_flag :ea_flag,                   label: 'Extended Attribute Flag'
      uint8                   :attribute_name_length,     label: 'Attribute Name Length',   initial_value: -> { attribute_name.length }
      uint16                  :attribute_value_length,    label: 'Attribute Value Length',  initial_value: -> { attribute_value.length }
      string                  :attribute_name,            label: 'Attribute Name'
      string                  :attribute_value,           label: 'Attribute Value'
    end
  end
end
