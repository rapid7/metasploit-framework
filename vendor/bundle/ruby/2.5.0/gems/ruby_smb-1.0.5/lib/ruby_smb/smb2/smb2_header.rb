module RubySMB
  module SMB2
    # Represents the Header of an SMB2 packet as defined in
    # [2.2.1.2 SMB2 Packet Header - SYNC](https://msdn.microsoft.com/en-us/library/cc246529.aspx)
    class SMB2Header < BinData::Record
      endian              :little
      bit32               :protocol,          label: 'Protocol ID Field',      initial_value: RubySMB::SMB2::SMB2_PROTOCOL_ID
      uint16              :structure_size,    label: 'Header Structure Size',  initial_value: 64
      uint16              :credit_charge,     label: 'Credit Charge',          initial_value: 0
      nt_status           :nt_status,         label: 'NT Status',              initial_value: 0
      uint16              :command,           label: 'Command'
      uint16              :credits,           label: 'Credit Request/Response'
      smb2_header_flags   :flags,             label: 'Flags'
      uint32              :next_command,      label: 'Command Chain Offset',   initial_value: 0
      uint64              :message_id,        label: 'Message ID',             initial_value: 0
      uint32              :process_id,        label: 'Process ID',             initial_value: 0x0000feff
      uint32              :tree_id,           label: 'Tree ID'
      uint64              :session_id,        label: 'Session ID'
      string              :signature,         label: 'Signature', length: 16
    end
  end
end
