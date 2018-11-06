module RubySMB
  module SMB1
    module Packet
      module NtTrans
        # Class representing a generic NT Transaction request packet as defined in
        # [2.2.4.62.1 Request](https://msdn.microsoft.com/en-us/library/ee441534.aspx)
        class Request < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT

          # The {RubySMB::SMB1::ParameterBlock} specific to this packet type.
          class ParameterBlock < RubySMB::SMB1::ParameterBlock
            endian :little
            uint8         :max_setup_count,       label: 'Max Setup Count'
            uint16        :reserved,              label: 'Reserved Space'
            uint32        :total_parameter_count, label: 'Total Parameter Count(bytes)'
            uint32        :total_data_count,      label: 'Total Data Count(bytes)'
            uint32        :max_parameter_count,   label: 'Max Parameter Count(bytes)'
            uint32        :max_data_count,        label: 'Max Data Count(bytes)'
            uint32        :parameter_count,       label: 'Parameter Count(bytes)',         initial_value: -> { parent.data_block.trans2_parameters.length }
            uint32        :parameter_offset,      label: 'Parameter Offset',               initial_value: -> { parent.data_block.trans2_parameters.abs_offset }
            uint32        :data_count,            label: 'Data Count(bytes)',              initial_value: -> { parent.data_block.trans2_data.length }
            uint32        :data_offset,           label: 'Data Offset',                    initial_value: -> { parent.data_block.trans2_data.abs_offset }
            uint8         :setup_count,           label: 'Setup Count',                    initial_value: -> { setup.length }
            uint16        :function,              label: 'Function'

            array :setup, type: :uint16, initial_length: 0
          end

          # The {RubySMB::SMB1::DataBlock} specific to this packet type.
          class DataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
            string :pad1, length: -> { pad1_length }
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
