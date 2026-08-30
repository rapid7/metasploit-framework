# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI DbgACK stream. It is an acknowledgement
        # directed to a server's distributed garbage collector that indicates that remote objects
        # in a return value from a server have been received by the client.
        class DgcAck < Element

          # @!attribute stream_id
          #   @return [Integer] the input stream id
          attr_accessor :stream_id
          # @!attribute unique_identifier
          #   @return [String] the unique identifier
          attr_accessor :unique_identifier

          private

          # Reads the stream id from the IO
          #
          # @param io [IO] the IO to read from
          # @return [String]
          # @raise [Rex::Proto::Rmi::DecodeError] if fails to decode stream id
          def decode_stream_id(io)
            stream_id = read_byte(io)
            unless stream_id == DGC_ACK_MESSAGE
              raise Rex::Proto::Rmi::DecodeError, 'Failed to decode DgcAck stream id'
            end

            stream_id
          end

          # Reads the unique identifier from the IO
          #
          # @param io [IO] the IO to read from
          # @return [String]
          def decode_unique_identifier(io)
            unique_identifier = read_string(io, 14)

            unique_identifier
          end

          # Encodes the stream_id field
          #
          # @return [String]
          def encode_stream_id
            [stream_id].pack('C')
          end

          # Encodes the unique_identifier field
          #
          # @return [String]
          def encode_unique_identifier
            unique_identifier
          end
        end
      end
    end
  end
end