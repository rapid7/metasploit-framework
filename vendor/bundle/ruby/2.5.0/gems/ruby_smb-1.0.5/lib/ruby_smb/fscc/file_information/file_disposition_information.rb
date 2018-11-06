module RubySMB
  module Fscc
    module FileInformation
      # The FileDispositionInformation Class as defined in
      # [2.4.11 FileDispositionInformation](https://msdn.microsoft.com/en-us/library/cc232098.aspx)
      class FileDispositionInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_DISPOSITION_INFORMATION

        endian :little

        uint8 :delete_pending, label: 'Delete Pending', initial_value: 0
      end
    end
  end
end
