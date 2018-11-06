module RubySMB
  module Fscc
    module FileInformation
      # The FileNamesInformation Class as defined in
      # [2.4.26 FileNamesInformation](https://msdn.microsoft.com/en-us/library/cc232077.aspx)
      class FileNamesInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_NAMES_INFORMATION

        endian :little

        uint32           :next_offset,      label: 'Next Entry Offset'
        uint32           :file_index,       label: 'File Index'
        uint32           :file_name_length, label: 'File Name Length',  initial_value: -> { file_name.do_num_bytes }
        string16         :file_name,        label: 'File Name',         read_length: -> { file_name_length }
      end
    end
  end
end
