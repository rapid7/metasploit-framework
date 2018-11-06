module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_READ_ANDX Request Packet as defined in
      # [2.2.4.42.1 Request](https://msdn.microsoft.com/en-us/library/ee441839.aspx)
      # [2.2.4.2.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/ff470250.aspx)
      class ReadAndxRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_READ_ANDX

        # A SMB1 Parameter Block as defined by the {ReadAndxRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little

          and_x_block :andx_block
          uint16      :fid,                          label: 'FID'
          uint32      :offset,                       label: 'Offset'
          uint16      :max_count_of_bytes_to_return, label: 'Max Count of Bytes to Return'
          uint16      :min_count_of_bytes_to_return, label: 'Min Count of Bytes to Return'

          choice :timeout_or_max_count_high, selection: -> { read_from_named_pipe } do
            struct true do
              uint32 :timeout,                       label: 'Timeout'
            end
            struct false do
              uint16 :max_count_high,                label: 'Max Count High'
              uint16 :reserved,                      label: 'Reserved'
            end
          end

          uint16      :remaining,                        label: 'Remaining',     initial_value: 0x0000
          uint32      :offset_high,                      label: 'Offset High',   onlyif: -> { word_count == 0x0C }

          # Specifies if the file to read is a named pipe or a regular file.
          # @return [TrueClass, FalseClass] true if reading from a named pipe, false otherwise
          attr_accessor :read_from_named_pipe

          def initialize_instance
            super
            @read_from_named_pipe = false
          end

          # Bypass the word count calculation to use 32-bit offset by default.
          # As a result, the optional offset_high field won't be defined until
          # #set_64_bit_offset(true) is explicitly called.
          def calculate_word_count
            0x0A
          end
          private :calculate_word_count
        end

        # Represents the specific layout of the DataBlock for a {ReadAndxRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        # Sets the read_from_named_pipe flag to `read_from_named_pipe` value (true or false).
        # When reading from a named pipe, this flag needs to be set to true, which forces
        # the use of Timeout field in Timeout_or_MaxCountHigh. When set to false (default),
        # for regular files, MaxCountHigh field will be used instead.
        #
        # @param read_from_named_pipe [TrueClass, FalseClass] the value the read_from_named_pipe flag is to be set to.
        def set_read_from_named_pipe(read_from_named_pipe)
          raise ArgumentError.new, 'The value can only be true or false' unless [true, false].include?(read_from_named_pipe)
          parameter_block.read_from_named_pipe = read_from_named_pipe
        end

        # Specifies whether the offset is a 32-bit (default) or 64-bit value. When `is_64_bit`
        # is true, a 64-bit offset will be used and the OffsetHigh field will be added to the structure.
        #
        # @param is_64_bit [TrueClass, FalseClass] use a 64-bit offset if set to true, 32-bit otherwise
        def set_64_bit_offset(is_64_bit)
          raise ArgumentError.new, 'The value can only be true or false' unless [true, false].include?(is_64_bit)
          parameter_block.word_count = is_64_bit ? 0x0C : 0x0A
        end
      end
    end
  end
end
