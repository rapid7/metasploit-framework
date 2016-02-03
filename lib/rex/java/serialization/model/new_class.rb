# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        # This class provides a NewArray (Java Array) representation
        class NewClass < Element

          include Rex::Java::Serialization::Model::Contents

          # @!attribute array_description
          #   @return [Java::Serialization::Model::ClassDesc] The description of the class
          attr_accessor :class_description

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          def initialize(stream = nil)
            super(stream)
            self.class_description = nil
          end

          # Deserializes a Rex::Java::Serialization::Model::NewClass
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [Rex::Java::Serialization::DecodeError] if deserialization doesn't succeed
          def decode(io)
            self.class_description = ClassDesc.decode(io, stream)
            stream.add_reference(self) unless stream.nil?

            self
          end

          # Serializes the Rex::Java::Serialization::Model::NewClass
          #
          # @return [String] if serialization succeeds
          # @raise [Rex::Java::Serialization::EncodeError] if serialization doesn't succeed
          def encode
            unless class_description.kind_of?(ClassDesc)
              raise Rex::Java::Serialization::EncodeError, 'Failed to serialize NewClass'
            end

            encoded = ''
            encoded << class_description.encode
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            print_content(class_description)
          end
        end
      end
    end
  end
end
