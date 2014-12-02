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
          # @return [nil] if deserialization isn't possible
          def decode(io)
            raw_length = io.read(2)
            return nil if raw_length.nil?
            self.length = raw_length.unpack('n')[0]

            if length == 0
              self.contents = ''
            else
              self.contents = io.read(length)
              return nil if contents.nil? || contents.length != length
            end

            self
          end

          # Serializes the Java::Serialization::Model::Utf
          #
          # @return [String] if serialization is possible
          # @return [nil] if serialization isn't possible
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