module Rex
  module Java
    module Serialization
      module Model
        # This class provides a NewArray (Java Array) representation
        class NewArray < Element

          include Rex::Java::Serialization

          # @!attribute array_description
          #   @return [Java::Serialization::Model::ClassDescription] The description of the array
          attr_accessor :array_description
          # @!attribute type
          #   @return [String] The type of the array values
          attr_accessor :type
          # @!attribute values
          #   @return [Array] The contents of the java array
          attr_accessor :values

          def initialize
            self.array_description = nil
            self.type = ''
            self.values = []
          end

          # Deserializes a Java::Serialization::Model::NewArray
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            self.array_description = ClassDesc.decode(io)
            self.type = array_type

            values_length = decode_values_length(io)

            values_length.times do
              value = decode_value(io)
              self.values << value
            end

            self
          end

          # Serializes the Java::Serialization::Model::NewArray
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            unless array_description.class == Rex::Java::Serialization::Model::ClassDesc
              raise ::RuntimeError, 'Failed to serialize NewArray'
            end

            encoded = ''
            encoded << array_description.encode

            encoded << [values.length].pack('N')

            values.each do |value|
              encoded << encode_value(value)
            end

            encoded
          end

          private

          # Deserializes the NewArray length
          #
          # @param io [IO] the io to read from
          # @return [Integer] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode_values_length(io)
            values_length = io.read(4)
            if values_length.nil? || values_length.length != 4
              raise ::RuntimeError, 'Failed to unserialize NewArray'
            end

            values_length.unpack('N')[0]
          end

          # Extracts the NewArray data type
          #
          # @return [String]
          # @raise [RuntimeError] if the NewArray description isn't valid
          # @raise [RuntimeError] if the NewArray type isn't supported
          def array_type
            if array_description.nil?
              raise ::RuntimeError, 'Empty NewArray description'
            end

            unless array_description.class == Rex::Java::Serialization::Model::ClassDesc
              raise ::RuntimeError, 'Unsupported NewArray description class'
            end

            desc = array_description.description

            unless desc.class_name.length == 2
              raise ::RuntimeError, 'Unsupported Complex NewArray deserialization'
            end

            unless desc.class_name.contents[0] == '[' # Array
              raise ::RuntimeError, 'Unsupported NewArray description'
            end

            unless PRIMITIVE_TYPE_CODES.keys.include?(desc.class_name.contents[1])
              raise ::RuntimeError, 'Unsupported NewArray of Object Type'
            end

            PRIMITIVE_TYPE_CODES[desc.class_name.contents[1]]
          end

          # Deserializes a NewArray value
          #
          # @param io [IO] the io to read from
          # @return [Fixnum] if deserialization succeeds
          # @return [Float] if deserialization succeeds
          # @raise [RuntimeError] if deserialization fails
          def decode_value(io)
            value = nil

            case type
            when 'byte'
              value = io.read(1)
              raise ::RuntimeError, 'Failed to deserialize NewArray value' if value.nil?
              value = value.unpack('c')[0]
            when 'char'
              value = io.read(2)
              unless value && value.length == 2
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value = value.unpack('s>')[0]
            when 'double'
              value = io.read(8)
              unless value && value.length == 8
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value = value.unpack('G')[0]
            when 'float'
              value = io.read(4)
              unless value && value.length == 4
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value = value.unpack('g')[0]
            when 'int'
              value = io.read(4)
              unless value && value.length == 4
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value = value.unpack('l>')[0]
            when 'long'
              value = io.read(8)
              unless value && value.length == 8
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value = value.unpack('q>')[0]
            when 'short'
              value = io.read(2)
              unless value && value.length == 2
                raise ::RuntimeError, 'Failed to deserialize NewArray value'
              end
              value = value.unpack('s>')[0]
            when 'boolean'
              value = io.read(1)
              raise ::RuntimeError, 'Failed to deserialize NewArray value' if value.nil?
              value = value.unpack('c')[0]
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

            case type
            when 'byte'
              res = [value].pack('c')
            when 'char'
              res = [value].pack('s>')
            when 'double'
              res = [value].pack('G')
            when 'float'
              res = [value].pack('g')
            when 'int'
              res = [value].pack('l>')
            when 'long'
              res = [value].pack('q>')
            when 'short'
              res = [value].pack('s>')
            when 'boolean'
              res = [value].pack('c')
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