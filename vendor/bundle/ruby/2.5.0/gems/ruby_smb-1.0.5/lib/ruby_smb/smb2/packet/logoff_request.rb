module RubySMB
  module SMB2
    module Packet
      # An SMB2 LOGOFF Request Packet as defined in
      # [2.2.7 SMB2 LOGOFF Request](https://msdn.microsoft.com/en-us/library/cc246565.aspx)
      class LogoffRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::LOGOFF

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 4
        uint16       :reserved,       label: 'Reserved Space'

      end
    end
  end
end
