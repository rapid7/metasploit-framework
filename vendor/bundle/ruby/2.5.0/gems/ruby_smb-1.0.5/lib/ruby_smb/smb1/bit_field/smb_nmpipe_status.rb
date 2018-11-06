module RubySMB
  module SMB1
    module BitField
      # The SMB Named Pipe Status data type as defined in
      # [2.2.1.3 Named Pipe Status (SMB_NMPIPE_STATUS)](https://msdn.microsoft.com/en-us/library/ee878732.aspx)
      class SmbNmpipeStatus < BinData::Record
        endian  :little
        bit8    :icount,      label: 'Number of Instances'
        # byte boundary
        bit1    :nonblocking, label: 'NonBlocking'
        bit1    :endpoint,    label: 'Endpoint'
        bit3    :reserved2,   label: 'Reserved'
        bit1    :nmpipe_type, label: 'Named Pipe Type'
        bit1    :reserved,    label: 'Reserved Space'
        bit1    :read_mode,   label: 'Read Mode'
      end
    end
  end
end
