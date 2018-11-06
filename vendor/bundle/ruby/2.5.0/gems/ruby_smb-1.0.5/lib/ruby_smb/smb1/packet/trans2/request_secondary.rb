module RubySMB
  module SMB1
    module Packet
      module Trans2
        # This class represents a generic SMB1 Trans2 Secondary Request Packet as defined in
        # [2.2.4.47.1 Request](https://msdn.microsoft.com/en-us/library/ee442105.aspx)
        class RequestSecondary < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2_SECONDARY

          # The {RubySMB::SMB1::ParameterBlock} specific to this packet type.
          class ParameterBlock < RubySMB::SMB1::ParameterBlock
            uint16 :total_parameter_count, label: 'Total Parameter Count(bytes)'
            uint16  :total_data_count,        label: 'Total Data Count(bytes)'
            uint16  :parameter_count,         label: 'Parameter Count(bytes)',         initial_value: -> { parent.data_block.trans2_parameters.length }
            uint16  :parameter_offset,        label: 'Parameter Offset',               initial_value: -> { parent.data_block.trans2_parameters.abs_offset }
            uint16  :parameter_displacement,  label: 'Parameter Displacement'
            uint16  :data_count,              label: 'Data Count(bytes)',              initial_value: -> { parent.data_block.trans2_data.length }
            uint16  :data_offset,             label: 'Data Offset',                    initial_value: -> { parent.data_block.trans2_data.abs_offset }
            uint16  :data_displacement,       label: 'Data Displacement'
            uint16  :fid,                     label: 'FileID'
          end

          # The {RubySMB::SMB1::DataBlock} specific to this packet type.
          class DataBlock < RubySMB::SMB1::Packet::Trans2::Request::DataBlock
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

        end
      end
    end
  end
end
