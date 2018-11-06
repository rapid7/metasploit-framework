module RubySMB
  module SMB2
    module Packet
      # An SMB2 Close Request Packet as defined in
      # [2.2.15 SMB2 CLOSE Request](https://msdn.microsoft.com/en-us/library/cc246523.aspx)
      class CloseRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::CLOSE

        endian :little

        smb2_header           :smb2_header
        uint16                :structure_size,        label: 'Structure Size', initial_value: 24
        uint16                :flags,                 label: 'Flags'
        uint32                :reserved,              label: 'Reserved Space'
        smb2_fileid           :file_id,               label: 'File ID'

      end
    end
  end
end
