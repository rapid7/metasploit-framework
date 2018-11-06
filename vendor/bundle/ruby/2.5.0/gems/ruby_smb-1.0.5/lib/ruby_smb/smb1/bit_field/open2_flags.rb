module RubySMB
  module SMB1
    module BitField
      # The Flags bit-field for an SMB1 Open2 Request as defined in
      # [2.2.6.1.1 Request](https://msdn.microsoft.com/en-us/library/ee441733.aspx)
      class Open2Flags < BinData::Record
        endian  :little
        bit4    :reserved,    label: 'Reserved Space'
        bit1    :req_easize,  label: 'Request EA Size',      initial_value: 1
        bit1    :req_opbatch, label: 'Request Batch OpLock', initial_value: 0
        bit1    :req_oplock,  label: 'Request OpLock',       initial_value: 0
        bit1    :req_attrib,  label: 'Request Attributes',   initial_value: 1
        # Byte boundary
        bit8    :reserved2,   label: 'Reserved Space'
      end
    end
  end
end
