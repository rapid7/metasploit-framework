# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        # This class provides a Long Utf string representation
        class LongUtf < Utf

          # Deserializes a Rex::Java::Serialization::Model::LongUtf
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [Rex::Java::Serialization::DecodeError] if deserialization doesn't succeed
          def decode(io)
            raw_length = io.read(8)
            if raw_length.nil? || raw_length.length != 8
              raise Rex::Java::Serialization::DecodeError, 'Failed to unserialize LongUtf'
            end
            self.length = raw_length.unpack('Q>')[0]

            if length == 0
              self.contents = ''
            else
              self.contents = io.read(length)
              if contents.nil? || contents.length != length
                raise Rex::Java::Serialization::DecodeError, 'Failed to unserialize LongUtf'
              end
            end

            self
          end

          # Serializes the Rex::Java::Serialization::Model::LongUtf
          #
          # @return [String]
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