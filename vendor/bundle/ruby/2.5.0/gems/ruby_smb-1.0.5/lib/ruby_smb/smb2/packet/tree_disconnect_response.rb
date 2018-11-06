module RubySMB
  module SMB2
    module Packet
      # An SMB2 TreeDisconnectResponse Packet as defined in
      # [2.2.12 SMB2 TREE_DISCONNECT Response](https://msdn.microsoft.com/en-us/library/cc246501.aspx)
      class TreeDisconnectResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::TREE_DISCONNECT

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 4

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
