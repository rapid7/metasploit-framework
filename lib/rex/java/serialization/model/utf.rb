module Rex
  module Java
    module Serialization
      module Model
        # This class provides a Utf string representation
        class Utf < Element

          # @!attribute length
          #   @return [Integer] the length of the string
          attr_accessor :length
          # @!attribute contents
          #   @return [String] the contents of the string
          attr_accessor :contents

          # @param contents [String] the contents of the utf string
          def initialize(contents = '')
            self.contents = contents
            self.length = contents.length
          end

          # Unserializes a Java::Serialization::Model::Utf
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization is possible
          # @raise [RuntimeError] if deserialization isn't possible
          def decode(io)
            raw_length = io.read(2)
            if raw_length.nil? || raw_length.length != 2
              raise ::RuntimeError, 'Failed to unserialize Utf'
            end
            self.length = raw_length.unpack('n')[0]

            if length == 0
              self.contents = ''
            else
              self.contents = io.read(length)
              if contents.nil? || contents.length != length
                raise ::RuntimeError, 'Failed to unserialize Utf'
              end
            end

            self
          end

          # Serializes the Java::Serialization::Model::Utf
          #
          # @return [String]
          def encode
            encoded = [length].pack('n')
            encoded << contents

            encoded
          end
        end
      end
    end
  end
end