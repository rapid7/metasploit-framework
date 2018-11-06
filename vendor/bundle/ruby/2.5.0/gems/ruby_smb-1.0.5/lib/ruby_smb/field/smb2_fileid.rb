module RubySMB
  module Field
    # Class representing an SMB2 FileID as defined in
    # [2.2.14.1 SMB2_FILEID](https://msdn.microsoft.com/en-us/library/cc246513.aspx)
    class Smb2Fileid < BinData::Record
      endian :little
      uint64   :persistent,  label: 'Persistent File Handle'
      uint64   :volatile,    label: 'Volatile File handle'
    end
  end
end
