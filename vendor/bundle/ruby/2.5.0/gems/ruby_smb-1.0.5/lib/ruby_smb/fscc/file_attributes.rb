module RubySMB
  module Fscc
    # The bit-field for File System Control Code File Attributes as defined in
    # [2.6 File Attributes](https://msdn.microsoft.com/en-us/library/cc232110.aspx)
    class FileAttributes < BinData::Record
      endian :little
      bit1  :normal,       label: 'Normal File/Directory'
      bit1  :device,       label: 'Device'
      bit1  :archive,      label: 'Archive'
      bit1  :directory,    label: 'Directory'
      bit1  :volume,       label: 'Volume Label'
      bit1  :system,       label: 'System File'
      bit1  :hidden,       label: 'Hidden File'
      bit1  :read_only,    label: 'Read Only'
      # Byte boundary
      bit1  :reserved,        label: 'Reserved Space'
      bit1  :encrypted,       label: 'File is Encrypted'
      bit1  :content_indexed, label: 'Content Indexed'
      bit1  :offline,         label: 'Offline Storage'
      bit1  :compressed,      label: 'Compressed File'
      bit1  :reparse_point,   label: 'Reparse Point'
      bit1  :sparse,          label: 'Sparse File'
      bit1  :temp,            label: 'Temporary File'
      # Byte boundary
      bit8  :reserved2,       label: 'Reserved Space'
      bit8  :reserved3,       label: 'Reserved Space'
    end
  end
end
