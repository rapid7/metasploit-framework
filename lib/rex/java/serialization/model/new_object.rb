# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        # This class provides a NewObject (Java Object) representation
        class NewObject < Element

          include Rex::Java::Serialization::Model::Contents

          # @!attribute class_desc
          #   @return [Rex::Java::Serialization::Model::ClassDesc] The description of the object
          attr_accessor :class_desc
          # @!attribute class_data
          #   @return [Array] The data of the object
          attr_accessor :class_data

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          def initialize(stream = nil)
            super(stream)
            self.class_desc = nil
            self.class_data = []
          end

          # Deserializes a Rex::Java::Serialization::Model::NewObject
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            self.class_desc = ClassDesc.decode(io, stream)
            stream.add_reference(self) unless stream.nil?

            case class_desc.description
            when NewClassDesc
              self.class_data = decode_class_data(io, class_desc.description)
            when Reference
              ref = class_desc.description.handle - BASE_WIRE_HANDLE
              self.class_data = decode_class_data(io, stream.references[ref])
            end

            self
          end

          # Serializes the Rex::Java::Serialization::Model::NewObject
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            unless class_desc.kind_of?(ClassDesc)
              raise ::RuntimeError, 'Failed to serialize NewObject'
            end

            encoded = ''
            encoded << class_desc.encode

            class_data.each do |value|
              if value.kind_of?(Array)
                encoded << encode_value(value)
              else
                encoded << encode_content(value)
              end
            end

            encoded
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            str  = ''
            case class_desc.description
            when NewClassDesc
              str << class_desc.description.class_name.to_s
            when Reference
              str << (class_desc.description.handle - BASE_WIRE_HANDLE).to_s(16)
            end

            str << ' => { '
            data_str = class_data.collect { |data| data.to_s }
            str << data_str.join(', ')
            str << ' }'
          end

          private

          # Deserializes the class_data for a class_desc and its super classes
          #
          # @param io [IO] the io to read from
          # @param my_class_desc [Rex::Java::Serialization::Model::NewClassDesc] the class description whose data is being extracted
          # @return [Array] class_data values if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode_class_data(io, my_class_desc)
            values = []

            unless my_class_desc.super_class.description.class == NullReference
              if my_class_desc.super_class.description.class == Reference
                ref = my_class_desc.super_class.description.handle - BASE_WIRE_HANDLE
                values += decode_class_data(io, stream.references[ref])
              else
                values += decode_class_data(io, my_class_desc.super_class.description)
              end
            end

            values += decode_class_fields(io, my_class_desc)

            values
          end

          # Deserializes the fields data for a class_desc
          #
          # @param io [IO] the io to read from
          # @param my_class_desc [Rex::Java::Serialization::Model::NewClassDesc] the class description whose data is being extracted
          # @return [Array] class_data values if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode_class_fields(io, my_class_desc)
            values = []

            my_class_desc.fields.each do |field|
              if field.is_primitive?
                values << decode_value(io, field.type)
              else
                content =  decode_content(io, stream)
                values << content
              end
            end

            values
          end

          # Deserializes a class_data value
          #
          # @param io [IO] the io to read from
          # @param type [String] the type of the value to deserialize
          # @return [Array(String, <Fixnum, Float>)] type and value if deserialization succeeds
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

          # Serializes an class_data value
          #
          # @param value [Array] the type and value to serialize
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
