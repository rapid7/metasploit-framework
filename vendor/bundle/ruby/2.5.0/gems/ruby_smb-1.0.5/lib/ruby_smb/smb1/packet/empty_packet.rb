module RubySMB
  module SMB1
    module Packet
      # This packet represent an SMB1 Error Response Packet when the parameter and
      # data blocks will be empty.
      class EmptyPacket < RubySMB::GenericPacket
        attr_accessor :original_command

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def valid?
          return smb_header.protocol == RubySMB::SMB1::SMB_PROTOCOL_ID &&
                 smb_header.command == @original_command &&
                 parameter_block.word_count == 0 &&
                 data_block.byte_count == 0
        end
      end
    end
  end
end
