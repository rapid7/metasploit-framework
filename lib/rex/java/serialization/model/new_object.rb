module Rex
  module Java
    module Serialization
      module Model
        # This class provides a NewObject (Java Object) representation
        class NewObject < Element

          include Rex::Java::Serialization

          # @!attribute array_description
          #   @return [Java::Serialization::Model::ClassDescription] The description of the object
          attr_accessor :class_desc
          attr_accessor :class_data

          def initialize
            self.class_desc = nil
            self.class_data = []
          end

          # Deserializes a Java::Serialization::Model::NewObject
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            self.class_desc = ClassDesc.decode(io)

            unless class_desc.description.super_class.description.class == Rex::Java::Serialization::Model::NullReference
              raise ::RuntimeError, 'Deserialization of objects with super classes not supported'
            end

            self.class_data = decode_class_data(io)

            self
          end

          # Serializes the Java::Serialization::Model::NewArray
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            unless class_desc.class == Rex::Java::Serialization::Model::ClassDesc
              raise ::RuntimeError, 'Failed to serialize NewObject'
            end

            encoded = ''
            encoded << class_desc.encode

            class_data.each do |value|
              encoded << encode_value(value)
            end

            encoded
          end

          private

          def decode_class_data(io)
            values = []

            class_desc.description.fields.each do |field|
              unless field.is_primitive?
                raise ::RuntimeError, 'Deserialization of objects with complex fields not supported'
              end

              values << decode_value(io, field.type)
            end

            values
          end

          # Deserializes a NewArray value
          #
          # @param io [IO] the io to read from
          # @return [Fixnum] if deserialization succeeds
          # @return [Float] if deserialization succeeds
          # @raise [RuntimeError] if deserialization fails
          def decode_value(io, type)
            value = []

            case type
            when 'byte'
              value_raw = io.read(1)
              raise ::RuntimeError, 'Failed to deserialize NewArray value' if value_raw.nil?
              value.push('byte', value_raw.unpack('c')[0])
            when 'char'
              value_raw = io.read(2)
              unless value_raw && value_raw.length == 2
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value.push('char', value_raw.unpack('s>')[0])
            when 'double'
              value_raw = io.read(8)
              unless value_raw && value_raw.length == 8
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value.push('double', value = value_raw.unpack('G')[0])
            when 'float'
              value_raw = io.read(4)
              unless value_raw && value_raw.length == 4
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value.push('float', value_raw.unpack('g')[0])
            when 'int'
              value_raw = io.read(4)
              unless value_raw && value_raw.length == 4
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value.push('int', value_raw.unpack('l>')[0])
            when 'long'
              value_raw = io.read(8)
              unless value_raw && value_raw.length == 8
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value.push('long', value_raw.unpack('q>')[0])
            when 'short'
              value_raw = io.read(2)
              unless value_raw && value_raw.length == 2
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value.push('short', value_raw.unpack('s>')[0])
            when 'boolean'
              value_raw = io.read(1)
              raise ::RuntimeError, 'Failed to deserialize NewArray value' if value_raw.nil?
              value.push('boolean', value_raw.unpack('c')[0])
            else
              raise ::RuntimeError, 'Unsupported NewArray type'
            end

            value
          end

          # Serializes an NewArray value
          #
          # @param value [Fixnum] the value to serialize
          # @param value [Float] the value to serialize
          # @return [String] the serialized value
          # @raise [RuntimeError] if serialization fails
          def encode_value(value)
            res = ''

            case value[0]
            when 'byte'
              res = [value[1]].pack('c')
            when 'char'
              res = [value[1]].pack('s>')
            when 'double'
              res = [value[1]].pack('G')
            when 'float'
              res = [value[1]].pack('g')
            when 'int'
              res = [value[1]].pack('l>')
            when 'long'
              res = [value[1]].pack('q>')
            when 'short'
              res = [value[1]].pack('s>')
            when 'boolean'
              res = [value[1]].pack('c')
            else
              raise ::RuntimeError, 'Unsupported NewArray type'
            end

            res
          end

        end
      end
    end
  end
end