# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI protocol ack input stream
        class ProtocolAck < Element

          # @!attribute stream_id
          #   @return [Integer] the input stream id
          attr_accessor :stream_id
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

          # Reads the stream id from the IO
          #
          # @param io [IO] the IO to read from
          # @return [String]
          # @raise [Rex::Proto::Rmi::DecodeError] if fails to decode stream id
          def decode_stream_id(io)
            stream_id = read_byte(io)
            unless stream_id == PROTOCOL_ACK
              raise Rex::Proto::Rmi::DecodeError, 'Failed to decode ProtocolAck stream id'
            end

            stream_id
          end

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

          # Encodes the stream_id field
          #
          # @return [String]
          def encode_stream_id
            [stream_id].pack('C')
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