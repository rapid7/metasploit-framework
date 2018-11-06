module RubySMB
  module Fscc
    module FileInformation
      # The FileRenameInformation Class as defined in
      # [2.4.34.2 FileRenameInformation](https://msdn.microsoft.com/en-us/library/cc704597.aspx)
      class FileRenameInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_ID_FULL_DIRECTORY_INFORMATION

        endian :little

        uint8  :replace_if_exists, label: 'Replace If Exists'

        choice :reserved, selection: -> { get_smb_version } do
          uint24 1, label: 'Reserved Space'
          uint56 2, label: 'Reserved Space'
        end

        choice :root_directory, selection: -> { get_smb_version } do
          uint32 1, label: 'Root Directory', initial_value: 0
          uint64 2, label: 'Root Directory', initial_value: 0
        end

        uint32 :file_name_length, label: 'File Name Length', initial_value: -> { file_name.do_num_bytes }
        string :file_name,        label: 'File Name',        read_length: -> { file_name_length }

        def get_smb_version(obj = self)
          # Return version 1 by default in case the structure is not part of a
          # SMB packet. This way, we can still instantiate this structure
          # independently without breaking the "choice" logic.
          return 1 if obj.nil?
          smb_version = if obj.respond_to?(:smb_header)
                          1
                        elsif obj.respond_to?(:smb2_header)
                          2
                        else
                          get_smb_version(obj.parent)
                        end
          return smb_version
        end

      end
    end
  end
end
