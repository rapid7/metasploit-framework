# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of UniqueIdentifier as used in RMI calls
        class UniqueIdentifier < Element

          # @!attribute number
          #   @return [Integer] Identifies the VM where an object is generated
          attr_accessor :number
          # @!attribute time
          #   @return [Integer] Time where the object was generated
          attr_accessor :time
          # @!attribute count
          #   @return [Integer] Identifies different instance of the same object generated from the same VM
          #     at the same time
          attr_accessor :count

          private

          # Reads the number from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          def decode_number(io)
            number = read_int(io)

            number
          end

          # Reads the time from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          def decode_time(io)
            time = read_long(io)

            time
          end

          # Reads the count from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          def decode_count(io)
            count = read_short(io)

            count
          end

          # Encodes the number field
          #
          # @return [String]
          def encode_number
            [number].pack('l>')
          end

          # Encodes the time field
          #
          # @return [String]
          def encode_time
            [time].pack('q>')
          end

          # Encodes the count field
          #
          # @return [String]
          def encode_count
            [count].pack('s>')
          end
        end
      end
    end
  end
end