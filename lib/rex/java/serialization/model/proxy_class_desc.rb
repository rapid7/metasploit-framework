# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        # This class provides a ProxyClassDesc representation
        class ProxyClassDesc < Element

          include Rex::Java::Serialization

          # @!attribute interfaces
          #   @return [Array] An array of interface names
          attr_accessor :interfaces
          # @!attribute class_annotation
          #   @return [Rex::Java::Serialization::Model::Annotation] The java class annotations
          attr_accessor :class_annotation
          # @!attribute super_class
          #   @return [Rex::Java::Serialization::Model::ClassDesc] The java class superclass description
          attr_accessor :super_class

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          def initialize(stream = nil)
            super(stream)
            self.interfaces = []
            self.class_annotation = nil
            self.super_class = nil
          end

          # Deserializes a Rex::Java::Serialization::Model::ProxyClassDesc
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [Rex::Java::Serialization::DecodeError] if deserialization doesn't succeed
          def decode(io)
            stream.add_reference(self) unless stream.nil?

            interfaces_length = decode_interfaces_length(io)
            interfaces_length.times do
              interface = Utf.decode(io, stream)
              self.interfaces << interface
            end
            self.class_annotation = Annotation.decode(io, stream)
            self.super_class = ClassDesc.decode(io, stream)

            self
          end

          # Serializes the Rex::Java::Serialization::Model::ProxyClassDesc
          #
          # @return [String] if serialization succeeds
          # @raise [Rex::Java::Serialization::EncodeError] if serialization doesn't succeed
          def encode
            unless class_annotation.class == Rex::Java::Serialization::Model::Annotation ||
                    super_class.class == Rex::Java::Serialization::Model::ClassDesc
              raise Rex::Java::Serialization::EncodeError, 'Failed to serialize ProxyClassDesc'
            end
            encoded = ''
            encoded << [interfaces.length].pack('N')
            interfaces.each do |interface|
              encoded << interface.encode
            end
            encoded << class_annotation.encode
            encoded << super_class.encode

            encoded
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            str = '[ '
            interfaces_str = []
            interfaces.each do |interface|
              interfaces_str << interface.to_s
            end
            str << "#{interfaces_str.join(', ')} ]"

            case super_class.description
            when NewClassDesc
              str << ", @super_class: #{super_class.description.class_name.to_s}"
            when Reference
              str << ", @super_class: #{super_class.description.to_s}"
            end

            str
          end

          private

          # Deserializes the number of interface names
          #
          # @param io [IO] the io to read from
          # @return [Fixnum] if deserialization is possible
          # @raise [Rex::Java::Serialization::DecodeError] if deserialization doesn't succeed
          def decode_interfaces_length(io)
            fields_length = io.read(4)
            if fields_length.nil? || fields_length.length != 4
              raise Rex::Java::Serialization::DecodeError, 'Failed to unserialize ProxyClassDesc'
            end

            fields_length.unpack('N')[0]
          end
        end
      end
    end
  end
end
