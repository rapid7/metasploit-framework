# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI return data stream
        class ReturnData < Element

          # @!attribute stream_id
          #   @return [Integer] the stream id
          attr_accessor :stream_id
          # @!attribute return value
          #   @return [Rex::Proto::Rmi::Model::ReturnValue] the return value
          attr_accessor :return_value

          private

          # Reads the stream id from the IO
          #
          # @param io [IO] the IO to read from
          # @return [String]
          # @raise [Rex::Proto::Rmi::DecodeError] if fails to decode the stream id
          def decode_stream_id(io)
            stream_id = read_byte(io)
            unless stream_id == RETURN_DATA
              raise Rex::Proto::Rmi::DecodeError, 'Failed to decode ReturnData stream id'
            end

            stream_id
          end

          # Reads and deserializes the return value from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Rex::Proto::Rmi::Model::ReturnValue]
          def decode_return_value(io)
            return_value = Rex::Proto::Rmi::Model::ReturnValue.decode(io)

            return_value
          end

          # Encodes the stream_id field
          #
          # @return [String]
          def encode_stream_id
            [stream_id].pack('C')
          end

          # Encodes the return_value field
          #
          # @return [String]
          def encode_return_value
            return_value.encode
          end
        end
      end
    end
  end
end