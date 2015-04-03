# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI call message
        class Call < Element

          # @!attribute message_id
          #   @return [Fixnum] the message id
          attr_accessor :message_id
          # @!attribute call_data
          #   @return [Rex::Java::Serialization::Model::Stream] the serialized call data
          attr_accessor :call_data

          private

          # Reads the message id from the IO
          #
          # @param io [IO] the IO to read from
          # @return [String]
          # @raise [RuntimeError] if fails to decode the message id
          def decode_message_id(io)
            message_id = read_byte(io)
            unless message_id == CALL_MESSAGE
              raise ::RuntimeError, 'Failed to decode Call message id'
            end

            message_id
          end

          # Reads and deserializes the call data from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Rex::Java::Serialization::Model::Stream]
          def decode_call_data(io)
            call_data = Rex::Java::Serialization::Model::Stream.decode(io)

            call_data
          end

          # Encodes the message_id field
          #
          # @return [String]
          def encode_message_id
            [message_id].pack('C')
          end

          # Encodes the address field
          #
          # @return [String]
          def encode_call_data
            call_data.encode
          end
        end
      end
    end
  end
end