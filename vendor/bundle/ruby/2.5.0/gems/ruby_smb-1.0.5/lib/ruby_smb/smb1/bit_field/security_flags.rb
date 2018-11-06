module RubySMB
  module SMB1
    module BitField
      # Represents a SecurityFlags BitField as used by both the SMB_COM_NT_CREATE_ANDX
      # and the NT_TRANSACT_CREATE Requests. The definition for this field can be found at
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      class SecurityFlags < BinData::Record
        endian  :little
        bit6    :reserved,         label: 'Reserved Space'
        bit1    :effective_only,   label: 'Effective Only'
        bit1    :context_tracking, label: 'Context Tracking'
      end
    end
  end
end
