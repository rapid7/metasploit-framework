module Rex
  module Java
    module Serialization
      module Model
        # This class provides a Java classDesc representation
        class ClassDesc < Element

          include Rex::Java::Serialization

          attr_accessor :description

          def initialize
            self.description = nil
          end

          # Deserializes a Java::Serialization::Model::ClassDesc
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            opcode = io.read(1)
            raise ::RuntimeError, 'Failed to unserialize ClassDesc' if opcode.nil?
            opcode = opcode.unpack('C')[0]

            case opcode
            when TC_NULL
              self.description = NullReference.new
            when TC_CLASSDESC
              self.description = NewClassDesc.decode(io)
            when TC_PROXYCLASSDESC
              #TODO: Support TC_PROXYCLASSDESC
              raise ::RuntimeError, 'ClassDesc unserialize failed due to unsupported class'
            when TC_REFERENCE
              #TODO: Support TC_REFERENCE
              raise ::RuntimeError, 'ClassDesc unserialize failed due to unsupported class'
            else
              raise ::RuntimeError, 'ClassDesc unserialize failed'
            end

            self
          end

          # Serializes the Java::Serialization::Model::ClassDesc
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            encoded = ''

            case description
            when NewClassDesc
              encoded << [TC_CLASSDESC].pack('C')
              encoded << description.encode
            when NullReference
              encoded << [TC_NULL].pack('C')
            else
              #TODO: support other superclass types
              raise RuntimeError, 'Failed to serialize ClassDesc'
            end

            encoded
          end
        end
      end
    end
  end
end