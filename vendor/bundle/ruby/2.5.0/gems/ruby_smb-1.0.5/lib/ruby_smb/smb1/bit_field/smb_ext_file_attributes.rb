module RubySMB
  module SMB1
    module BitField
      # The bit-field for SMB1 Extended File Attributes as defined in
      # [2.2.1.2.3 SMB_EXT_FILE_ATTR](https://msdn.microsoft.com/en-us/library/ee878573.aspx) and
      # [2.2.1.2.1 Extended File Attribute (SMB_EXT_FILE_ATTR) Extensions](https://msdn.microsoft.com/en-us/library/cc246322.aspx)
      class SmbExtFileAttributes < BinData::Record
        endian :little
        bit1  :normal,              label: 'Normal File'
        bit1  :reserved,            label: 'Reserved Space'
        bit1  :archive,             label: 'Archive'
        bit1  :directory,           label: 'Directory'
        bit1  :reserved2,           label: 'Reserved Space'
        bit1  :system,              label: 'System File'
        bit1  :hidden,              label: 'Hidden File'
        bit1  :read_only,           label: 'Read Only'
        # Byte boundary
        bit1  :reserved3,           label: 'Reserved Space'
        bit1  :encrypted,           label: 'Encrypted'
        bit1  :not_content_indexed, label: 'Not Content Indexed'
        bit1  :offline,             label: 'Offline'
        bit1  :compressed,          label: 'Compressed File'
        bit1  :reparse_point,       label: 'Reparse Point'
        bit1  :sparse,              label: 'Sparse File'
        bit1  :temporary,           label: 'Temporary File'
        # Byte Boundary
        bit8  :reserved4,           label: 'Reserved Space'
        bit8  :reserved5,           label: 'Reserved Space'
      end
    end
  end
end
