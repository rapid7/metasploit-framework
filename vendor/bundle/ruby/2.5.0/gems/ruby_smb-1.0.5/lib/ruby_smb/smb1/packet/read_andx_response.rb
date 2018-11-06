module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_READ_ANDX Response Packet as defined in
      # [2.2.4.42.2 Response](https://msdn.microsoft.com/en-us/library/ee441872.aspx)
      # [2.2.4.2.2 Server Response Extensions](https://msdn.microsoft.com/en-us/library/ff470017.aspx)
      class ReadAndxResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_READ_ANDX

        # A SMB1 Parameter Block as defined by the {ReadAndxResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little
          and_x_block :andx_block
          uint16      :available,            label: 'Available'
          uint16      :data_compaction_mode, label: 'Data Compaction Mode', initial_value: 0x0000
          uint16      :reserved,             label: 'Reserved'
          uint16      :data_length,          label: 'Data Length'
          uint16      :data_offset,          label: 'Data Offset'
          uint16      :data_length_high,     label: 'Data Length High'
          uint64      :reserved2,            label: 'Reserved'
        end

        # Represents the specific layout of the DataBlock for a {ReadAndxResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          uint8  :pad,  label: 'Pad',  onlyif: -> { has_padding? }
          string :data, label: 'Data', read_length: -> { parent.parameter_block.data_length }

          # This method checks if the optional pad field is present in the response.
          def has_padding?
            return false if byte_count.zero?
            return true if byte_count - parent.parameter_block.data_length == 1
            false
          end
          private :has_padding?
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
