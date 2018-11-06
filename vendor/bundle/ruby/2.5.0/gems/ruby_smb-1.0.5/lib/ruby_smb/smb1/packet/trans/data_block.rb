module RubySMB
  module SMB1
    module Packet
      module Trans

        # Extends the {RubySMB::SMB1::DataBlock} to include padding methods
        # that all Trans DataBlocks will need to handle proper byte alignment.
        class DataBlock < RubySMB::SMB1::DataBlock
          # Controls whether the padding fields will be used
          # @!attribute [rw] enable_padding
          #   @return [Boolean]
          attr_accessor :enable_padding

          def initialize_instance
            super
            @enable_padding = true
          end

          private

          # Determines the correct length for the padding in front of
          # #trans_parameters. It should always force a 4-byte alignment.
          def pad1_length
            if enable_padding
              if self.respond_to?(:name)
                offset = (name.abs_offset + name.to_binary_s.length) % 4
              else
                offset = (byte_count.abs_offset + 2) % 4
              end
              (4 - offset) % 4
            else
              0
            end
          end

          # Determines the correct length for the padding in front of
          # #trans_data. It should always force a 4-byte alignment.
          def pad2_length
            if enable_padding
              offset = (trans_parameters.abs_offset + trans_parameters.length) % 4
              (4 - offset) % 4
            else
              0
            end
          end

          # Determines the correct length for the padding in front of
          # #name. It should always force a 2-byte alignment.
          def pad_name_length
            if enable_padding
              offset = (byte_count.abs_offset + 2) % 2
              (2 - offset) % 2
            else
              0
            end
          end
        end
      end
    end
  end
end
