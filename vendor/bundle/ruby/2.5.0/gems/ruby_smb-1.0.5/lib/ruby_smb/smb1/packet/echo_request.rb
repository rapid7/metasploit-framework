module RubySMB
  module SMB1
    module Packet
      # This class represents an SMB1 Echo Request Packet as defined in
      # [2.2.4.39.1 Request](https://msdn.microsoft.com/en-us/library/ee441746.aspx)
      class EchoRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_ECHO

        # The {RubySMB::SMB1::ParameterBlock} specific to this packet type.
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          uint16 :echo_count, label: 'Echo Count', initial_value: 1
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type.
        class DataBlock < RubySMB::SMB1::DataBlock
          string :data, label: 'Data'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

      end
    end
  end
end
