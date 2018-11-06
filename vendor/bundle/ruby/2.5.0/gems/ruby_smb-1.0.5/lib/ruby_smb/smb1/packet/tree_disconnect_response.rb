module RubySMB
  module SMB1
    module Packet
      # This class represents an SMB1 TreeDisonnect Response Packet as defined in
      # [2.2.4.51.2 Response](https://msdn.microsoft.com/en-us/library/ee441823.aspx)
      class TreeDisconnectResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_TREE_DISCONNECT

        # The Parameter Block for this packet is empty save the Word Count
        # The {RubySMB::SMB1::ParameterBlock} specific to this packet type.
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
        end

        # The Data Block for this packet is empty save the Byte Count
        class DataBlock < RubySMB::SMB1::DataBlock
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.flags.reply = 1
        end
      end
    end
  end
end
