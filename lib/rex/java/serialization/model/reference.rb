# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        # This class provides a Java Reference representation.
        class Reference < Element

          # @!attribute contents
          #   @return [Fixnum] The stream handle being referenced
          attr_accessor :handle

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          def initialize(stream = nil)
            super(stream)
            self.handle = 0
          end

          # Deserializes a Rex::Java::Serialization::Model::Reference
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            handle_raw = io.read(4)
            unless handle_raw && handle_raw.length == 4
              raise ::RuntimeError, 'Failed to unserialize Reference'
            end

            self.handle = handle_raw.unpack('N')[0]

            self
          end

          # Serializes the Rex::Java::Serialization::Model::Reference
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            if handle < BASE_WIRE_HANDLE
              raise ::RuntimeError, 'Failed to serialize Reference'
            end

            encoded = ''
            encoded << [handle].pack('N')

            encoded
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            "0x#{handle.to_s(16)}"
          end
        end
      end
    end
  end
end