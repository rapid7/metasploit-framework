module Rex
  module Java
    module Serialization
      module Model
        # This class provides an annotation representation. It's used for both class
        # annotations (classAnnotation) and object annotations (objectAnnotation).
        class Annotation < Element

          include Rex::Java::Serialization::Model::Contents

          # @!attribute contents
          #   @return [Array] The annotation contents
          attr_accessor :contents

          def initialize
            self.contents = []
          end

          # Deserializes a Java::Serialization::Model::Annotation
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            loop do
              content = decode_content(io)
              self.contents << content
              return self if content.class == Rex::Java::Serialization::Model::EndBlockData
            end

            self
          end

          # Serializes the Java::Serialization::Model::Annotation
          #
          # @return [String] if serialization suceeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            raise ::RuntimeError, 'Failed to serialize Annotation with empty contents' if contents.empty?

            encoded = ''

            contents.each do |content|
              encoded << encode_content(content)
            end

            encoded
          end

        end
      end
    end
  end
end