# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI Ping stream. A Ping is a message for testing
        # livereness of a remote virtual machine.
        class Ping < Element

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
            unless stream_id == PING_MESSAGE
              raise Rex::Proto::Rmi::DecodeError, 'Failed to decode Ping stream id'
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