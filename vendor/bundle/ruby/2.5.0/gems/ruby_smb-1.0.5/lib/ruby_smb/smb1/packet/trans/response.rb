module RubySMB
  module SMB1
    module Packet
      module Trans

        # This class represents a generic SMB1 Trans Response Packet as defined in
        # [2.2.4.33.2 Response](https://msdn.microsoft.com/en-us/library/ee442061.aspx)
        class Response < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION

          # A SMB1 Parameter Block
          class ParameterBlock < RubySMB::SMB1::ParameterBlock
            uint16 :total_parameter_count,  label: 'Total Parameter Count(bytes)', initial_value: -> { parameter_count }
            uint16 :total_data_count,       label: 'Total Data Count(bytes)',      initial_value: -> { data_count }
            uint16 :reserved,               label: 'Reserved Space',         value: 0x0000
            uint16 :parameter_count,        label: 'Parameter Count(bytes)', initial_value: -> { parent.data_block.trans_parameters.length }
            uint16 :parameter_offset,       label: 'Parameter Offset',       initial_value: -> { parent.data_block.trans_parameters.abs_offset }
            uint16 :parameter_displacement, label: 'Parameter Displacement'
            uint16 :data_count,             label: 'Data Count(bytes)',      initial_value: -> { parent.data_block.trans_data.length }
            uint16 :data_offset,            label: 'Data Offset',            initial_value: -> { parent.data_block.trans_data.abs_offset }
            uint16 :data_displacement,      label: 'Data Displacement'
            uint8  :setup_count,            label: 'Setup Count',            initial_value: -> { setup.length }
            uint8  :reserved2,              label: 'Reserved Space',         value: 0x00
            array  :setup,                  type:  :uint16,                  initial_length: :setup_count
          end

          class DataBlock < RubySMB::SMB1::Packet::Trans::DataBlock
            string :pad1,             length: lambda { pad1_length }
            string :trans_parameters, label: 'Trans Parameters', read_length: -> { parent.parameter_block.parameter_count }
            string :pad2,             length: lambda { pad2_length }
            string :trans_data,       label: 'Trans Data',       read_length: -> { parent.parameter_block.data_count }
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
end

