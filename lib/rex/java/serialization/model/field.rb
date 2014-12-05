module Rex
  module Java
    module Serialization
      module Model
        # This class provides a field description representation (fieldDesc). It's used for
        # both primitive descriptions (primitiveDesc) and object descriptions (objectDesc).
        class Field < Element

          include Rex::Java::Serialization::Model::Contents

          # @!attribute type
          #   @return [String] The type of the field.
          attr_accessor :type
          # @!attribute name
          #   @return [Java::Serialization::Model::Utf] The name of the field.
          attr_accessor :name
          # @!attribute field_type
          #   @return [Java::Serialization::Model::Utf] The type of the field on object types.
          attr_accessor :field_type

          def initialize(stream = nil)
            super(stream)
            self.type = ''
            self.name = nil
            self.field_type = nil
          end

          # Deserializes a Java::Serialization::Model::Field
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @faise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            code = io.read(1)

            unless code && is_valid?(code)
              raise ::RuntimeError, 'Failed to unserialize Field'
            end

            self.type = TYPE_CODES[code]
            self.name = Utf.decode(io)

            if is_object?
              self.field_type = decode_field_type(io)
            end

            self
          end

          # Serializes the Java::Serialization::Model::Field
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            unless name.class == Java::Serialization::Model::Utf
              raise ::RuntimeError, 'Failed to serialize Field'
            end

            unless is_type_valid?
              raise ::RuntimeError, 'Failed to serialize Field'
            end

            encoded = ''
            encoded << TYPE_CODES.key(type)
            encoded << name.encode

            if is_object?
                encoded << encode_field_type
            end

            encoded
          end

          # Whether the field type is valid.
          #
          # @return [Boolean]
          def is_type_valid?
            if TYPE_CODES.values.include?(type)
              return true
            end

            false
          end

          # Whether the field type is a primitive one.
          #
          # @return [Boolean]
          def is_primitive?
            if PRIMITIVE_TYPE_CODES.values.include?(type)
              return true
            end

            false
          end

          # Whether the field type is an object one.
          #
          # @return [Boolean]
          def is_object?
            if OBJECT_TYPE_CODES.values.include?(type)
              return true
            end

            false
          end

          private

          # Whether the type opcode is a valid one.
          #
          # @param code [String] A type opcode
          # @return [Boolean]
          def is_valid?(code)
            if TYPE_CODES.keys.include?(code)
              return true
            end

            false
          end

          # Serializes the `field_type` attribute.
          #
          # @return [String]
          def encode_field_type
            unless field_type.class == Java::Serialization::Model::Utf
              raise ::RuntimeError, 'Failed to serialize Field'
            end

            encoded = encode_content(field_type)

            encoded
          end

          # Deserializes the `field_type` value.
          #
          # @param io [IO] the io to read from
          # @return [Java::Serialization::Model::Utf]
          # @raise [RuntimeError] if unserialization doesn't succeed
          def decode_field_type(io)
            type = decode_content(io)

            unless type.class == Rex::Java::Serialization::Model::Utf || type.class == Rex::Java::Serialization::Model::Reference
              raise ::RuntimeError, 'Failed to unserialize Field field_type'
            end

            type
          end
        end
      end
    end
  end
end