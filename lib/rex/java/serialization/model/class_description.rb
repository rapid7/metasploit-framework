module Rex
  module Java
    module Serialization
      module Model
        # This class provides a class description representation
        class ClassDescription < Element

          include Rex::Java::Serialization

          # @!attribute class_name
          #   @return [Java::Serialization::Model::Utf] The name of the class
          attr_accessor :class_name
          # @!attribute name
          #   @return [Integer] The java class serial version
          attr_accessor :serial_version
          # @!attribute flags
          #   @return [Integer] The java class flags
          attr_accessor :flags
          # @!attribute fields
          #   @return [Array] The java class fields
          attr_accessor :fields
          # @!attribute fields
          #   @return [Java::Serialization::Model::Annotation] The java class annotations
          attr_accessor :class_annotation
          # @!attribute super_class
          #   @return [Java::Serialization::Model::ClassDescription] The java class superclass description
          #   @return [nil] it the java class hasn't superclass
          attr_accessor :super_class

          def initialize
            self.class_name = nil
            self.serial_version = 0
            self.flags = 0
            self.fields = []
            self.class_annotation = nil
            self.super_class = nil
          end

          # Unserializes a Java::Serialization::Model::ClassDescription
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization is possible
          # @raise [RuntimeError] if deserialization isn't possible
          def decode(io)
            self.class_name = Utf.decode(io)
            self.serial_version = decode_serial_version(io)
            self.flags = decode_flags(io)
            fields_length = decode_fields_length(io)

            fields_length.times do
              field = Field.decode(io)
              self.fields << field
            end

            self.class_annotation = Annotation.decode(io)
            self.super_class = decode_super_class(io)

            self
          end

          # Serializes the Java::Serialization::Model::ClassDescription
          #
          # @return [String] if serialization is possible
          # @raise [RuntimeError] if serialization isn't possible
          def encode
            encoded = ''
            encoded << class_name.encode
            encoded << [serial_version].pack('Q>')
            encoded << [flags].pack('C')
            encoded << [fields.length].pack('n')
            fields.each do |field|
              encoded << field.encode
            end
            encoded << class_annotation.encode

            case super_class
            when Rex::Java::Serialization::Model::ClassDescription
              encoded << [TC_CLASSDESC].pack('C')
              encoded << super_class.encode
            when nil
              encoded << [TC_NULL].pack('C')
            else
              #TODO: support other superclass types
              raise RuntimeError, 'Failed to serialize ClassDescription'
            end

            encoded
          end

          private

          # Unserializes a class serial version
          #
          # @param io [IO] the io to read from
          # @return [Integer] if deserialization is possible
          # @raise [RuntimeError] if deserialization isn't possible
          def decode_serial_version(io)
            raw_serial = io.read(8)
            if raw_serial.nil? || raw_serial.length != 8
              raise ::RuntimeError, 'Failed to unserialize ClassDescription'
            end

            raw_serial.unpack('Q>')[0]
          end

          # Unserializes a class flags
          #
          # @param io [IO] the io to read from
          # @return [Integer] if deserialization is possible
          # @raise [RuntimeError] if deserialization isn't possible
          def decode_flags(io)
            raw_flags = io.read(1)
            raise ::RuntimeError, 'Failed to unserialize ClassDescription' if raw_flags.nil?

            raw_flags.unpack('C')[0]
          end

          # Unserializes a class fields length
          #
          # @param io [IO] the io to read from
          # @return [Integer] if deserialization is possible
          # @raise [RuntimeError] if deserialization isn't possible
          def decode_fields_length(io)
            fields_length = io.read(2)
            if fields_length.nil? || fields_length.length != 2
              raise ::RuntimeError, 'Failed to unserialize ClassDescription'
            end

            fields_length.unpack('n')[0]
          end

          # Unserializes a class fields length
          #
          # @param io [IO] the io to read from
          # @return [nil] if there isn't superclass
          # @return [Rex::Java::Serialization::ClassDescription] superclass description
          # @raise [RuntimeError] if deserialization isn't possible
          # @raise [RuntimeError] if superclass isn't supported
          def decode_super_class(io)
            super_opcode = io.read(1)
            raise ::RuntimeError, 'Failed to unserialize ClassDescription' if super_opcode.nil?
            super_opcode = super_opcode.unpack('C')[0]

            class_desc = nil

            case super_opcode
            when TC_NULL
              class_desc = nil
            when TC_CLASSDESC
              class_desc = ClassDescription.decode(io)
            else
              #TODO: Support TC_PROXYCLASSDESC
              raise RuntimeError, 'unsupported super class'
            end

            class_desc
          end
        end
      end
    end
  end
end