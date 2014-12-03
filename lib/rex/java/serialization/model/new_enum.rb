module Rex
  module Java
    module Serialization
      module Model
        # This class provides a NewEnum (Java Enum) representation
        class NewEnum < Element

          include Rex::Java::Serialization

          # @!attribute enum_description
          #   @return [Java::Serialization::Model::ClassDescription] The description of the enum
          attr_accessor :enum_description
          # @!attribute constant_name
          #   @return [Array] The constant value in the Java Enum
          attr_accessor :constant_name

          def initialize
            self.enum_description = nil
            self.constant_name = nil
          end

          # Unserializes a Java::Serialization::Model::NewEnum
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            self.enum_description = ClassDesc.decode(io)
            self.constant_name = decode_constant_name(io)

            self
          end

          # Serializes the Java::Serialization::Model::NewEnum
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            unless enum_description.class == Rex::Java::Serialization::Model::ClassDesc &&
                    constant_name.class == Rex::Java::Serialization::Model::Utf
              raise ::RuntimeError, 'Failed to serialize EnumDescription'
            end

            encoded = ''
            encoded << enum_description.encode
            encoded << [TC_STRING].pack('C')
            encoded << constant_name.encode
            encoded
          end

          private

          # Deserializes the NewEnum constant name
          #
          # @param io [IO] the io to read from
          # @return [Rex::Java::Serialization::Model::Utf] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succed
          def decode_constant_name(io)
            opcode = io.read(1)
            unless opcode && opcode.unpack('C')[0] == TC_STRING
              raise ::RuntimeError, 'Failed to unserialize NewEnum'
            end

            constant = Utf.decode(io)

            constant
          end
        end
      end
    end
  end
end