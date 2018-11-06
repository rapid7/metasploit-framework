module RubySMB
  module SMB2
    module Packet
      # An SMB2 Read Response Packet as defined in
      # [2.2.40 SMB2 SET_INFO Response](https://msdn.microsoft.com/en-us/library/cc246562.aspx)
      class SetInfoResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::SET_INFO

        endian :little

        smb2_header   :smb2_header
        uint16        :structure_size, label: 'Structure Size', initial_value: 2

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
