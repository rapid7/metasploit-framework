# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI PingAck stream. A PingAck is the acknowledgement
        # for a Ping message.
        class PingAck < Element

          # @!attribute stream_id
          #   @return [Integer] the input stream id
          attr_accessor :stream_id

          private

          # Reads the stream id from the IO
          #
          # @param io [IO] the IO to read from
          # @return [String]
          # @raise [Rex::Proto::Rmi::DecodeError] if fails to decode stream id
          def decode_stream_id(io)
            stream_id = read_byte(io)
            unless stream_id == PING_ACK
              raise Rex::Proto::Rmi::DecodeError, 'Failed to decode PingAck stream id'
            end

            stream_id
          end

          # Encodes the stream_id field
          #
          # @return [String]
          def encode_stream_id
            [stream_id].pack('C')
          end
        end
      end
    end
  end
end