module RubySMB
  module SMB2
    module Packet
      # An SMB2 LOGOFF Response Packet as defined in
      # [2.2.8 SMB2 LOGOFF Response](https://msdn.microsoft.com/en-us/library/cc246566.aspx)
      class LogoffResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::LOGOFF

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 4
        uint16       :reserved,       label: 'Reserved Space'

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
