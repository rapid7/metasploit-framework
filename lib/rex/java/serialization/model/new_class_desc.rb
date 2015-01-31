# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        # This class provides a newClassDesc representation
        class NewClassDesc < Element

          include Rex::Java::Serialization

          # @!attribute class_name
          #   @return [Rex::Java::Serialization::Model::Utf] The name of the class
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
          #   @return [Rex::Java::Serialization::Model::Annotation] The java class annotations
          attr_accessor :class_annotation
          # @!attribute super_class
          #   @return [Rex::Java::Serialization::Model::ClassDesc] The java class superclass description
          attr_accessor :super_class

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          def initialize(stream = nil)
            super(stream)
            self.class_name = nil
            self.serial_version = 0
            self.flags = 0
            self.fields = []
            self.class_annotation = nil
            self.super_class = nil
          end

          # Deserializes a Rex::Java::Serialization::Model::ClassDescription
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            self.class_name = Utf.decode(io, stream)
            self.serial_version = decode_serial_version(io)
            stream.add_reference(self) unless stream.nil?
            self.flags = decode_flags(io)
            fields_length = decode_fields_length(io)
            fields_length.times do
              field = Field.decode(io, stream)
              self.fields << field
            end

            self.class_annotation = Annotation.decode(io, stream)
            self.super_class = ClassDesc.decode(io, stream)

            self
          end

          # Serializes the Rex::Java::Serialization::Model::ClassDescription
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            unless class_name.kind_of?(Rex::Java::Serialization::Model::Utf) &&
                   class_annotation.kind_of?(Rex::Java::Serialization::Model::Annotation) &&
                   super_class.kind_of?(Rex::Java::Serialization::Model::ClassDesc)
              raise ::RuntimeError, 'Filed to serialize NewClassDesc'
            end
            encoded = ''
            encoded << class_name.encode
            encoded << [serial_version].pack('Q>')
            stream.add_reference(self) unless stream.nil?
            encoded << [flags].pack('C')
            encoded << [fields.length].pack('n')
            fields.each do |field|
              encoded << field.encode
            end
            encoded << class_annotation.encode
            encoded << super_class.encode

            encoded
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            str = "#{class_name}, [ "
            fields_str = []
            fields.each do |field|
              fields_str << field.to_s
            end
            str << "#{fields_str.join(', ')} ]"

            case super_class.description
            when NewClassDesc
              str << ", @super_class: #{super_class.description.class_name.to_s}"
            when Reference
              str << ", @super_class: #{super_class.description.to_s}"
            end

            str
          end

          private

          # Deserializes a class serial version
          #
          # @param io [IO] the io to read from
          # @return [Integer] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode_serial_version(io)
            raw_serial = io.read(8)
            if raw_serial.nil? || raw_serial.length != 8
              raise ::RuntimeError, 'Failed to unserialize ClassDescription'
            end

            raw_serial.unpack('Q>')[0]
          end

          # Deserializes a class flags
          #
          # @param io [IO] the io to read from
          # @return [Integer] if deserialization is possible
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode_flags(io)
            raw_flags = io.read(1)
            raise ::RuntimeError, 'Failed to unserialize ClassDescription' if raw_flags.nil?

            raw_flags.unpack('C')[0]
          end

          # Deserializes a class fields length
          #
          # @param io [IO] the io to read from
          # @return [Integer] if deserialization is possible
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode_fields_length(io)
            fields_length = io.read(2)
            if fields_length.nil? || fields_length.length != 2
              raise ::RuntimeError, 'Failed to unserialize ClassDescription'
            end

            fields_length.unpack('n')[0]
          end
        end
      end
    end
  end
end
