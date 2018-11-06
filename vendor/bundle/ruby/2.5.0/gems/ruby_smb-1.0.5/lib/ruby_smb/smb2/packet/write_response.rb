module RubySMB
  module SMB2
    module Packet
      # An SMB2 Write Response Packet as defined in
      # [2.2.22 SMB2 WRITE Response](https://msdn.microsoft.com/en-us/library/cc246533.aspx)
      class WriteResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::WRITE

        endian :little

        smb2_header           :smb2_header
        uint16                :structure_size,        label: 'Structure Size',  initial_value: 17
        uint16                :reserved,              label: 'Reserved Space'
        uint32                :write_count,           label: 'Bytes Written'
        uint32                :remaining_bytes,       label: 'Remaining Bytes'
        uint16                :channel_offset,        label: 'Write Channel Info Offset'
        uint16                :channel_length,        label: 'Write Channel Info Length'


        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
