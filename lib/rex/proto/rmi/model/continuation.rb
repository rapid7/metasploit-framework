# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI continuation stream
        class Continuation < Element

          # @!attribute length
          #   @return [Integer] the end point address length
          attr_accessor :length
          # @!attribute address
          #   @return [String] the end point address
          attr_accessor :address
          # @!attribute port
          #   @return [Integer] the end point port
          attr_accessor :port

          private

          # Reads the end point identifier address length from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          def decode_length(io)
            length = read_short(io)

            length
          end

          # Reads the end point address from the IO
          #
          # @param io [IO] the IO to read from
          # @return [String]
          def decode_address(io)
            version = read_string(io, length)

            version
          end

          # Reads the end point port from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          def decode_port(io)
            port = read_int(io)

            port
          end

          # Encodes the length field
          #
          # @return [String]
          def encode_length
            [length].pack('n')
          end

          # Encodes the address field
          #
          # @return [String]
          def encode_address
            address
          end

          # Encodes the port field
          #
          # @return [String]
          def encode_port
            [port].pack('N')
          end
        end
      end
    end
  end
end