module Rex
  module Java
    module Serialization
      module Model
        # This class provides a Long Utf string representation
        class LongUtf < Utf
          # Unserializes a Java::Serialization::Model::LongUtf
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization is possible
          # @return [nil] if deserialization isn't possible
          def decode(io)
            raw_length = io.read(8)
            return nil if raw_length.nil?
            self.length = raw_length.unpack('Q>')[0]

            if length == 0
              self.contents = ''
            else
              self.contents = io.read(length)
              return nil if contents.nil? || contents.length != length
            end

            self
          end

          # Serializes the Java::Serialization::Model::LongUtf
          #
          # @return [String] if serialization is possible
          # @return [nil] if serialization isn't possible
          def encode
            encoded = [length].pack('Q>')
            encoded << contents

            encoded
          end
        end
      end
    end
  end
end