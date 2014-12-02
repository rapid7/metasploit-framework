module Rex
  module Java
    module Serialization
      module Model
        # This class provides an annotation representation. It's used for both class
        # annotations (classAnnotation) and object annotations (objectAnnotation).
        class Annotation < Element

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
          # @return [nil] if deserialization isn't possible
          # @raise [RuntimeError] if unsupported contents
          def decode(io)
            loop do
              opcode = io.read(1)
              return nil if opcode.nil?
              opcode = opcode.unpack('C')[0]

              case opcode
              when Rex::Java::Serialization::TC_BLOCKDATA
                block = BlockData.decode(io)
                return nil if block.nil?
                self.contents << block
              when Rex::Java::Serialization::TC_BLOCKDATALONG
                block = BlockDataLong.decode(io)
                return nil if block.nil?
                self.contents << block
              when Rex::Java::Serialization::TC_ENDBLOCKDATA
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
          # @return [nil] if serialization isn't possible
          # @raise [RuntimeError] if unsupported contents
          def encode
            encoded = ''

            contents.each do |content|
              case content
              when Rex::Java::Serialization::Model::BlockData
                encoded << [Rex::Java::Serialization::TC_BLOCKDATA].pack('C')
              when Rex::Java::Serialization::Model::BlockDataLong
                encoded << [Rex::Java::Serialization::TC_BLOCKDATALONG].pack('C')
              else
                raise ::RuntimeError, 'Unsupported content'
              end
              encoded_content = content.encode
              return nil if encoded_content.nil?
              encoded << encoded_content
            end

            encoded << [Rex::Java::Serialization::TC_ENDBLOCKDATA].pack('C')

            encoded
          end

        end
      end
    end
  end
end