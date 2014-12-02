module Rex
  module Java
    module Serialization
      module Model
        # This class provides a block data representation
        class BlockData < Element

          # @!attribute length
          #   @return [Integer] the length of the block
          attr_accessor :length
          # @!attribute contents
          #   @return [String] the contents of the block
          attr_accessor :contents

          # @param contents [String] the contents of the block
          def initialize(contents = '')
            self.contents = contents
            self.length = contents.length
          end

          # Unserializes a Java::Serialization::Model::BlockData
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization is possible
          # @raise [RuntimeError] if deserialization isn't possible
          def decode(io)
            raw_length = io.read(1)
            raise RuntimeError, 'Failed to unserialize BlockData' if raw_length.nil?
            self.length = raw_length.unpack('C')[0]

            if length == 0
              self.contents = ''
            else
              self.contents = io.read(length)
              if contents.nil? || contents.length != length
                raise RuntimeError, 'Failed to unserialize BlockData'
              end
            end

            self
          end

          # Serializes the Java::Serialization::Model::BlockData
          #
          # @return [String]
          def encode
            encoded = [length].pack('C')
            encoded << contents

            encoded
          end
        end
      end
    end
  end
end