# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        # This class provides a Java classDesc representation
        class ClassDesc < Element

          include Rex::Java::Serialization::Model::Contents

          attr_accessor :description

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          def initialize(stream = nil)
            super(stream)
            self.description = nil
          end

          # Deserializes a Rex::Java::Serialization::Model::ClassDesc
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            content = decode_content(io, stream)
            allowed_contents = [NullReference, NewClassDesc, Reference]

            unless allowed_contents.include?(content.class)
              raise ::RuntimeError, 'ClassDesc unserialize failed'
            end

            self.description = content
            self
          end

          # Serializes the Rex::Java::Serialization::Model::ClassDesc
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            encoded = ''
            allowed_contents = [NullReference, NewClassDesc, Reference]

            unless allowed_contents.include?(description.class)
              raise ::RuntimeError, 'Failed to serialize ClassDesc'
            end

            encoded << encode_content(description)

            encoded
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            print_content(description)
          end
        end
      end
    end
  end
end