# -*- coding: binary -*-

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

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          def initialize(stream = nil)
            super(stream)
            self.contents = []
          end

          # Deserializes a Rex::Java::Serialization::Model::Annotation
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            loop do
              content = decode_content(io, stream)
              self.contents << content
              return self if content.kind_of?(EndBlockData)
            end

            self
          end

          # Serializes the Rex::Java::Serialization::Model::Annotation
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

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            str = '[ '
            contents_data = contents.collect {|content| "#{print_content(content)}"}
            str << contents_data.join(', ')
            str << ' ]'
            str
          end

        end
      end
    end
  end
end
