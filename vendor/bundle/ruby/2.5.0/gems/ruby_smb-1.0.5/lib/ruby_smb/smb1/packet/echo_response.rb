module RubySMB
  module SMB1
    module Packet
      # This class represents an SMB1 Echo Request Packet as defined in
      # [2.2.4.39.2 Response](https://msdn.microsoft.com/en-us/library/ee441626.aspx)
      class EchoResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_ECHO

        # The {RubySMB::SMB1::ParameterBlock} specific to this packet type.
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          uint16 :sequence_number, label: 'Sequence Number'
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type.
        class DataBlock < RubySMB::SMB1::DataBlock
          string :data, label: 'Data'
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
