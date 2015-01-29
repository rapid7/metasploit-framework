# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        # This class provides a NewEnum (Java Enum) representation
        class NewEnum < Element

          include Rex::Java::Serialization::Model::Contents

          # @!attribute enum_description
          #   @return [Rex::Java::Serialization::Model::ClassDescription] The description of the enum
          attr_accessor :enum_description
          # @!attribute constant_name
          #   @return [Rex::Java::Serialization::Model::Utf] The constant value in the Java Enum
          attr_accessor :constant_name

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          def initialize(stream = nil)
            super(stream)
            self.enum_description = nil
            self.constant_name = nil
          end

          # Deserializes a Rex::Java::Serialization::Model::NewEnum
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            self.enum_description = ClassDesc.decode(io, stream)
            stream.add_reference(self) unless stream.nil?
            self.constant_name = decode_constant_name(io)

            self
          end

          # Serializes the Rex::Java::Serialization::Model::NewEnum
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            unless enum_description.kind_of?(ClassDesc) &&
                   constant_name.kind_of?(Utf)
              raise ::RuntimeError, 'Failed to serialize EnumDescription'
            end

            encoded = ''
            encoded << enum_description.encode
            encoded << encode_content(constant_name)
            encoded
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            constant_name.to_s
          end

          private

          # Deserializes the NewEnum constant name
          #
          # @param io [IO] the io to read from
          # @return [Rex::Java::Serialization::Model::Utf] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succed
          def decode_constant_name(io)
            content = decode_content(io, stream)
            raise ::RuntimeError, 'Failed to unserialize NewEnum' unless content.kind_of?(Rex::Java::Serialization::Model::Utf)

            content
          end
        end
      end
    end
  end
end
