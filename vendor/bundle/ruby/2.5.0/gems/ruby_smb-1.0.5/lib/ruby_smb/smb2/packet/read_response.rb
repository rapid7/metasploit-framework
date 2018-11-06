module RubySMB
  module SMB2
    module Packet
      # An SMB2 Read Response Packet as defined in
      # [2.2.20 SMB2 READ Response](https://msdn.microsoft.com/en-us/library/cc246531.aspx)
      class ReadResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::READ

        endian :little

        smb2_header   :smb2_header
        uint16        :structure_size,  label: 'Structure Size',      initial_value: 17
        uint8         :data_offset,     label: 'Data Buffer Offset',  initial_value: -> { buffer.abs_offset }
        uint8         :reserved,        label: 'Reserved Space'
        uint32        :data_length,     label: 'Data Buffer Length'
        uint32        :data_remaining,  label: 'Data Remaining'
        uint32        :reserved2,       label: 'Reserved Space'
        string        :buffer,          label: 'Data Buffer', length: -> { data_length }

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
