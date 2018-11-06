module RubySMB
  module SMB2
    module BitField
      # The Flags bit-field for an SMB2 Header as defined in
      # [2.2.1.2 SMB2 Packet Header - SYNC](https://msdn.microsoft.com/en-us/library/cc246529.aspx)
      class Smb2HeaderFlags < BinData::Record
        endian  :little
        bit4    :reserved3,           label: 'Reserved', initial_value: 0
        bit1    :signed,              label: 'Packet Signed'
        bit1    :related_operations,  label: 'Chained Request'
        bit1    :async_command,       label: 'ASYNC Command', initial_value: 0
        bit1    :reply,               label: 'Response'
        # byte border
        uint16  :reserved2,           label: 'Reserved',           initial_value: 0
        # byte border
        bit2    :reserved1,           label: 'Reserved',           initial_value: 0
        bit1    :replay_operation,    label: 'Replay Operation'
        bit1    :dfs_operation,       label: 'DFS Operation'
        resume_byte_alignment
      end
    end
  end
end
