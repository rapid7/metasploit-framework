module RubySMB
  module SMB1
    module Packet
      module Trans

        # This class represents a generic SMB1 Trans Request Packet as defined in
        # [2.2.4.33.1 Request](https://msdn.microsoft.com/en-us/library/ee441730.aspx)
        class Request < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION

          # A SMB1 Parameter Block
          class ParameterBlock < RubySMB::SMB1::ParameterBlock
            uint16      :total_parameter_count, label: 'Total Parameter Count(bytes)', initial_value: -> { parameter_count }
            uint16      :total_data_count,      label: 'Total Data Count(bytes)',      initial_value: -> { data_count }
            uint16      :max_parameter_count,   label: 'Max Parameter Count(bytes)',   initial_value: Trans::MAX_PARAMETER_COUNT
            uint16      :max_data_count,        label: 'Max Data Count(bytes)',        initial_value: Trans::MAX_DATA_COUNT
            uint8       :max_setup_count,       label: 'Max Setup Count',              initial_value: Trans::MAX_SETUP_COUNT
            uint8       :reserved,              label: 'Reserved Space',         value: 0x00
            trans_flags :flags
            uint32      :timeout,               label: 'Timeout',                initial_value: 0x00000000
            uint16      :reserved2,             label: 'Reserved Space',         value: 0x0000
            uint16      :parameter_count,       label: 'Parameter Count(bytes)', initial_value: -> { parent.data_block.trans_parameters.length }
            uint16      :parameter_offset,      label: 'Parameter Offset',       initial_value: -> { parent.data_block.trans_parameters.abs_offset }
            uint16      :data_count,            label: 'Data Count(bytes)',      initial_value: -> { parent.data_block.trans_data.length }
            uint16      :data_offset,           label: 'Data Offset',            initial_value: -> { parent.data_block.trans_data.abs_offset }
            uint8       :setup_count,           label: 'Setup Count',            initial_value: -> { setup.length }
            uint8       :reserved3,             label: 'Reserved Space',         value: 0x00
            array       :setup,                 type:  :uint16,                  initial_length: :setup_count
          end

          # The {RubySMB::SMB1::DataBlock} specific to this packet type.
          class DataBlock < RubySMB::SMB1::Packet::Trans::DataBlock
            # If unicode is set, the name field must be aligned to start on a 2-byte
            # boundary from the start of the SMB header:
            string :pad_name, length: -> { pad_name_length },
                              onlyif: -> { parent.smb_header.flags2.unicode.to_i == 1 }
            choice :name, :selection      => lambda { parent.smb_header.flags2.unicode.to_i },
                          :copy_on_change => true do
              stringz   0, label: 'Name', initial_value: "\\PIPE\\"
              stringz16 1, label: 'Name', initial_value: "\\PIPE\\".encode('utf-16le')

            end
            string :pad1,             length: lambda { pad1_length }
            string :trans_parameters, label: 'Trans Parameters', read_length: -> { parent.parameter_block.parameter_count }
            string :pad2,             length: lambda { pad2_length }
            string :trans_data,       label: 'Trans Data',       read_length: -> { parent.parameter_block.data_count }
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

        end
      end
    end
  end
end

