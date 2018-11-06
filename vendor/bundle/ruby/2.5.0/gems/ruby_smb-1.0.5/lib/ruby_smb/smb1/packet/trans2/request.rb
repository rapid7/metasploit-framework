module RubySMB
  module SMB1
    module Packet
      module Trans2
        # This class represents a generic SMB1 Trans2 Request Packet as defined in
        # [2.2.4.46.1 Request](https://msdn.microsoft.com/en-us/library/ee442192.aspx)
        class Request < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          # The {RubySMB::SMB1::ParameterBlock} specific to this packet type.
          class ParameterBlock < RubySMB::SMB1::ParameterBlock
            uint16        :total_parameter_count, label: 'Total Parameter Count(bytes)'
            uint16        :total_data_count,      label: 'Total Data Count(bytes)'
            uint16        :max_parameter_count,   label: 'Max Parameter Count(bytes)'
            uint16        :max_data_count,        label: 'Max Data Count(bytes)'
            uint8         :max_setup_count,       label: 'Max Setup Count'
            uint8         :reserved,              label: 'Reserved Space',         initial_value: 0x00
            trans_flags   :flags
            uint32        :timeout,               label: 'Timeout',                initial_value: 0x00000000
            uint16        :reserved2,             label: 'Reserved Space',         initial_value: 0x00
            uint16        :parameter_count,       label: 'Parameter Count(bytes)', initial_value: -> { parent.data_block.trans2_parameters.length }
            uint16        :parameter_offset,      label: 'Parameter Offset',       initial_value: -> { parent.data_block.trans2_parameters.abs_offset }
            uint16        :data_count,            label: 'Data Count(bytes)',      initial_value: -> { parent.data_block.trans2_data.length }
            uint16        :data_offset,           label: 'Data Offset',            initial_value: -> { parent.data_block.trans2_data.abs_offset }
            uint8         :setup_count,           label: 'Setup Count',            initial_value: -> { setup.length }
            uint8         :reserved3,             label: 'Reserved Space',         initial_value: 0x00

            array :setup, type: :uint16, initial_length: 0
          end

          # The {RubySMB::SMB1::DataBlock} specific to this packet type.
          class DataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
            uint8  :name,               label: 'Name', initial_value: 0x00
            string :pad1,               length: -> { pad1_length }
            string :trans2_parameters,  label: 'Trans2 Parameters'
            string :pad2,               length: -> { pad2_length }
            string :trans2_data,        label: 'Trans2 Data'
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

        end
      end
    end
  end
end
