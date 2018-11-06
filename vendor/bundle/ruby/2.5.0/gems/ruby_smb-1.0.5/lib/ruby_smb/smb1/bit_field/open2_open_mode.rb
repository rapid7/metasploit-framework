module RubySMB
  module SMB1
    module BitField
      # The OpenMode bit-field for an SMB1 Open2 Request as defined in
      # [2.2.6.1.1 Request](https://msdn.microsoft.com/en-us/library/ee441733.aspx)
      class Open2OpenMode < BinData::Record
        endian  :little
        bit3    :reserved2,           label: 'Reserved Space'
        bit1    :create_file,         label: 'Create File Options'
        bit2    :reserved,            label: 'Reserved Space'
        bit2    :file_exists_opts,    label: 'File Exists Options'
        # byte boundary
        bit8    :reserved5,           label: 'Reserved Space'
      end
    end
  end
end
