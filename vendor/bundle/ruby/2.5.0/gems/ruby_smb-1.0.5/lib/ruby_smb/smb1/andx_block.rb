module RubySMB
  module SMB1
    # Represents the ANDX Block in SMB1 ANDX Command Packets
    # [2.2.3.4 Batched Messages ("AndX" Messages)](https://msdn.microsoft.com/en-us/library/ee442210.aspx)
    class AndXBlock < BinData::Record
      endian :little

      bit8  :andx_command,   label: 'Next Command Code',  initial_value: RubySMB::SMB1::Commands::SMB_COM_NO_ANDX_COMMAND
      bit8  :andx_reserved,  label: 'AndX Reserved',      initial_value: 0x00
      bit16 :andx_offset,    label: 'Andx Offset',        initial_value: 0x00
    end
  end
end
