module RubySMB
  module Fscc
    module FileInformation
      # The FileDirectoryInformation Class as defined in
      # [2.4.10 FileDirectoryInformation](https://msdn.microsoft.com/en-us/library/cc232097.aspx)
      class FileDirectoryInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_DIRECTORY_INFORMATION

        endian :little

        uint32           :next_offset,      label: 'Next Entry Offset'
        uint32           :file_index,       label: 'File Index'
        file_time        :create_time,      label: 'Create Time'
        file_time        :last_access,      label: 'Last Accessed Time'
        file_time        :last_write,       label: 'Last Write Time'
        file_time        :last_change,      label: 'Last Modified Time'
        uint64           :end_of_file,      label: 'End of File'
        uint64           :allocation_size,  label: 'Allocated Size'
        file_attributes  :file_attributes,  label: 'File Attributes'
        uint32           :file_name_length, label: 'File Name Length',  initial_value: -> { file_name.do_num_bytes }
        string16         :file_name,        label: 'File Name',         read_length: -> { file_name_length }
      end
    end
  end
end
