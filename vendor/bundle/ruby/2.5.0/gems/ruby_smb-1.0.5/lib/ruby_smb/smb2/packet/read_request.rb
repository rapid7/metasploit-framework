module RubySMB
  module SMB2
    module Packet
      # An SMB2 Read Request Packet as defined in
      # [2.2.19 SMB2 READ Request](https://msdn.microsoft.com/en-us/library/cc246527.aspx)
      class ReadRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::READ

        endian :little

        smb2_header           :smb2_header
        uint16                :structure_size,        label: 'Structure Size',  initial_value: 49
        uint8                 :padding,               label: 'Padding',         initial_value: 0x50
        uint8                 :flags,                 label: 'Flags'
        uint32                :read_length,           label: 'Read Length'
        uint64                :offset,                label: 'Read Offset'
        smb2_fileid           :file_id,               label: 'File ID'
        uint32                :min_bytes,             label: 'Minimum Count'
        uint32                :channel,               label: 'Channel'
        uint32                :remaining_bytes,       label: 'Remaining Bytes'
        uint16                :channel_offset,        label: 'Read Channel Info Offset'
        uint16                :channel_length,        label: 'Read Channel Info Length'
        string                :buffer,                label: 'Read Channel info Buffer', initial_value: 0x00

      end
    end
  end
end
