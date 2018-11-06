module RubySMB
  module SMB1
    module BitField
      # Represents a FileStatusFlags BitField as used by both the SMB_COM_NT_CREATE_ANDX
      # and the NT_TRANSACT_CREATE Responses. The definition for this field can be found at
      # [2.2.4.9.2 Server Response Extensions](https://msdn.microsoft.com/en-us/library/cc246334.aspx)
      class FileStatusFlags < BinData::Record
        endian  :little
        bit5    :reserved,      label: 'Reserved'
        bit1    :reparse_tag,   label: 'No Reparse Tag'
        bit1    :no_substreams, label: 'No Data Sream'
        bit1    :no_eas,        label: 'No Extended Attributes (EAs)'
        # byte boundary
        bit8    :reserved2,     label: 'Reserved'
      end
    end
  end
end
