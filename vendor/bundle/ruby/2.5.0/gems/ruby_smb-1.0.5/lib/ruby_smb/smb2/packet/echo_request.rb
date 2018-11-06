module RubySMB
  module SMB2
    module Packet
      # An SMB2 Echo Request Packet as defined in
      # [2.2.28 SMB2 ECHO Request](https://msdn.microsoft.com/en-us/library/cc246540.aspx)
      class EchoRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::ECHO

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 4
        uint16       :reserved

      end
    end
  end
end
