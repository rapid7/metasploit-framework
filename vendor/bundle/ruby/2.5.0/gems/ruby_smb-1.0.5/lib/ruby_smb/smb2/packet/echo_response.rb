module RubySMB
  module SMB2
    module Packet
      # An SMB2 Echo response Packet as defined in
      # [2.2.29 SMB2 ECHO Response](https://msdn.microsoft.com/en-us/library/cc246541.aspx)
      class EchoResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::ECHO

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 4
        uint16       :reserved

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
