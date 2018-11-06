module RubySMB
  module SMB1
    module BitField
      # The Flags bit-field for SMB1 File Attributes as defined in
      # [2.2.1.2.4 SMB_FILE_ATTRIBUTES](https://msdn.microsoft.com/en-us/library/ee441551.aspx)
      class SmbFileAttributes < BinData::Record
        endian :little
        bit2  :reserved,     label: 'Reserved Space'
        bit1  :archive,      label: 'Archive'
        bit1  :directory,    label: 'Directory'
        bit1  :volume,       label: 'Volume Label'
        bit1  :system,       label: 'System File'
        bit1  :hidden,       label: 'Hidden File'
        bit1  :read_only,    label: 'Read Only'
        # Byte boundary
        bit2  :reserved2,         label: 'Reserved Space'
        bit1  :search_archive,    label: 'Search for Archive Files'
        bit1  :search_directory,  label: 'Search for Directories'
        bit1  :reserved3,         label: 'Reserved Space'
        bit1  :search_system,     label: 'Search for System Files'
        bit1  :search_hidden,     label: 'Search for Hidden Files'
        bit1  :search_read_only,  label: 'Search for Read Only Files'
      end
    end
  end
end
