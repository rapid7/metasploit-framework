module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_WRITE_ANDX Request Packet as defined in
      # [2.2.4.43.1 Request](https://msdn.microsoft.com/en-us/library/ee441954.aspx)
      # [2.2.4.3.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/ff469893.aspx)
      class WriteAndxRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_WRITE_ANDX

        # A SMB1 Parameter Block as defined by the {WriteAndxRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian      :little

          and_x_block :andx_block
          uint16      :fid,                  label: 'FID'
          uint32      :offset,               label: 'Offset'
          uint32      :timeout,              label: 'Timeout'

          struct      :write_mode,           label: 'Write Mode' do
            bit4      :reserved,             label: 'Reserved Space'
            bit1      :msg_start,            label: 'Message Start'
            bit1      :raw_mode,             label: 'Raw Mode'
            bit1      :read_bytes_available, label: 'Read Bytes Available'
            bit1      :writethrough_mode,    label: 'Writethrough Mode'
            # byte boundary
            bit8      :reserved2,            label: 'Reserved Space'
          end

          uint16      :remaining,            label: 'Remaining'
          uint16      :data_length_high,     label: 'Data Length High'
          uint16      :data_length,          label: 'Data Length(bytes)', value: -> { parent.data_block.data.length }
          uint16      :data_offset,          label: 'Data Offset',        value: -> { parent.data_block.data.abs_offset }
          uint32      :offset_high,          label: 'Offset High',        onlyif: -> { word_count == 0x0E }

          # Bypass the word count calculation to use 32-bit offset by default.
          # As a result, the optional offset_high field won't be defined until
          # #set_64_bit_offset(true) is explicitly called.
          def calculate_word_count
            0x0C
          end
          private :calculate_word_count
        end

        # Represents the specific layout of the DataBlock for a {WriteAndxRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          uint8  :pad,  label: 'Pad'
          string :data, label: 'Data'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        # Specifies whether the offset is a 32-bit (default) or 64-bit value. When `is_64_bit`
        # is true, a 64-bit offset will be used and the OffsetHigh field will be added to the structure.
        #
        # @param is_64_bit [TrueClass, FalseClass] use a 64-bit offset if set to true, 32-bit otherwise
        def set_64_bit_offset(is_64_bit)
          raise ArgumentError.new, 'The value can only be true or false' unless [true, false].include?(is_64_bit)
          parameter_block.word_count = is_64_bit ? 0x0E : 0x0C
        end
      end
    end
  end
end
