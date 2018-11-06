module RubySMB
  module SMB1
    module Packet
      module NtTrans
        # Class representing a generic NT Transaction response packet as defined in
        # [2.2.4.62.2 Response](https://msdn.microsoft.com/en-us/library/ee442112.aspx)
        class Response < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT

          # The {RubySMB::SMB1::ParameterBlock} specific to this packet type.
          class ParameterBlock < RubySMB::SMB1::ParameterBlock
            endian :little

            array :reserved, type: :uint8, inital_length: 3

            uint32        :total_parameter_count,   label: 'Total Parameter Count(bytes)'
            uint32        :total_data_count,        label: 'Total Data Count(bytes)'
            uint32        :parameter_count,         label: 'Parameter Count(bytes)',         initial_value: -> { parent.data_block.trans2_parameters.length }
            uint32        :parameter_offset,        label: 'Parameter Offset',               initial_value: -> { parent.data_block.trans2_parameters.abs_offset }
            uint32        :parameter_displacement,  label: 'Parameter Displacement'
            uint32        :data_count,              label: 'Data Count(bytes)',              initial_value: -> { parent.data_block.trans2_data.length }
            uint32        :data_offset,             label: 'Data Offset',                    initial_value: -> { parent.data_block.trans2_data.abs_offset }
            uint32        :data_displacement,       label: 'Data Displacement'
            uint8         :setup_count,             label: 'Setup Count', initial_value: -> { setup.length }

            array :setup, type: :uint16, initial_length: 0
          end

          # The {RubySMB::SMB1::DataBlock} specific to this packet type.
          class DataBlock < RubySMB::SMB1::Packet::NtTrans::Request::DataBlock
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
