module RubySMB
  module Fscc
    # Class representing a FillFullEaInformation structure as defined in
    # [2.4.15 FileFullEaInformation](https://msdn.microsoft.com/en-us/library/cc232069.aspx)
    class FileFullEaInfo < BinData::Record
      endian :little
      uint32                  :next_entry_offset, label: 'Next Entry Offset'
      extended_attribute_flag :flags
      uint8                   :ea_name_length,    label: 'EA Name Length',  initial_value: -> { ea_name.do_num_bytes }
      uint8                   :ea_value_length,   label: 'EA Value Length', initial_value: -> { ea_value.do_num_bytes }
      string                  :ea_name,           label: 'EA Name'
      string                  :ea_value,          label: 'EA Value'
    end
  end
end
