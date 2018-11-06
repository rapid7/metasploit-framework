module RubySMB
  module SMB2
    module Packet
      # An SMB2 Write Request Packet as defined in
      # [2.2.21 SMB2 WRITE Request](https://msdn.microsoft.com/en-us/library/cc246532.aspx)
      class WriteRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::WRITE

        endian :little

        smb2_header           :smb2_header
        uint16                :structure_size,        label: 'Structure Size',  initial_value: 49
        uint16                :data_offset,           label: 'Data Offset' ,    initial_value: lambda { self.buffer.abs_offset }
        uint32                :write_length,          label: 'Write Length',    initial_value: lambda { self.buffer.do_num_bytes }
        uint64                :write_offset,          label: 'File Write Offset'
        smb2_fileid           :file_id,               label: 'File ID'
        uint32                :channel,               label: 'Channel'
        uint32                :remaining_bytes,       label: 'Remaining Bytes'
        uint16                :channel_offset,        label: 'Write Channel Info Offset'
        uint16                :channel_length,        label: 'Write Channel Info Length'
        uint32                :flags,                 label: 'Flags'
        string                :buffer,                label: 'Write Data Buffer'

      end
    end
  end
end
