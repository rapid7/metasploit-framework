module RubySMB
  module SMB1
    module Packet
      # This class represents an SMB1 LOGOFF Request Packet as defined in
      # [2.2.4.54.1 Request](https://msdn.microsoft.com/en-us/library/ee442167.aspx)
      class LogoffRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_LOGOFF

        # The Parameter Block for this packet is empty save the Word Count and ANDX Block
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          and_x_block :andx_block
        end

        # The Data Block for this packet is empty save the Byte Count
        class DataBlock < RubySMB::SMB1::DataBlock
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

      end
    end
  end
end
