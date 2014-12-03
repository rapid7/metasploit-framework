module Rex
  module Java
    module Serialization
      module Model
        # This class provides an annotation representation. It's used for both class
        # annotations (classAnnotation) and object annotations (objectAnnotation).
        class Annotation < Element

          include Rex::Java::Serialization

          # @!attribute contents
          #   @return [Array] The annotation contents
          attr_accessor :contents

          def initialize
            self.contents = []
          end

          # Unserializes a Java::Serialization::Model::Annotation
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization is possible
          # @raise [RuntimeError] if deserialization isn't possible
          def decode(io)
            loop do
              opcode = io.read(1)
              if opcode.nil?
                raise ::RuntimeError, 'Failed to unserialize Annotation'
              end
              opcode = opcode.unpack('C')[0]

              case opcode
              when TC_BLOCKDATA
                block = BlockData.decode(io)
                self.contents << block
              when TC_BLOCKDATALONG
                block = BlockDataLong.decode(io)
                self.contents << block
              when TC_ENDBLOCKDATA
                return self
              else
                #TODO: unsupported
                raise ::RuntimeError, 'Unsupported content opcode'
              end
            end

            self
          end

          # Serializes the Java::Serialization::Model::Annotation
          #
          # @return [String] if serialization is possible
          # @raise [RuntimeError] if serialization isn't possible
          def encode
            encoded = ''

            contents.each do |content|
              case content
              when Rex::Java::Serialization::Model::BlockData
                encoded << [TC_BLOCKDATA].pack('C')
              when Rex::Java::Serialization::Model::BlockDataLong
                encoded << [TC_BLOCKDATALONG].pack('C')
              else
                raise ::RuntimeError, 'Unsupported content'
              end
              encoded_content = content.encode
              encoded << encoded_content
            end

            encoded << [TC_ENDBLOCKDATA].pack('C')

            encoded
          end

        end
      end
    end
  end
end