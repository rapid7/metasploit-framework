# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI return data stream
        class ReturnData < Element

          # @!attribute stream_id
          #   @return [Fixnum] the stream id
          attr_accessor :stream_id
          # @!attribute return value
          #   @return [Rex::Java::Serialization::Model::Stream] the serialized return data
          attr_accessor :return_value

          private

          # Reads the stream id from the IO
          #
          # @param io [IO] the IO to read from
          # @return [String]
          # @raise [RuntimeError] if fails to decode the stream id
          def decode_stream_id(io)
            stream_id = read_byte(io)
            unless stream_id == RETURN_DATA
              raise ::RuntimeError, 'Failed to decode ReturnData stream id'
            end

            stream_id
          end

          # Reads and deserializes the return value from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Rex::Java::Serialization::Model::Stream]
          def decode_return_value(io)
            return_value = Rex::Java::Serialization::Model::Stream.decode(io)

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