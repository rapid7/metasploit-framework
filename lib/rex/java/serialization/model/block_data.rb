# -*- coding: binary -*-

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

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          # @param contents [String] the contents of the block
          def initialize(stream = nil, contents = '')
            super(stream)
            self.contents = contents
            self.length = contents.length
          end

          # Deserializes a Rex::Java::Serialization::Model::BlockData
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
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

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            contents_hex = []
            contents.each_byte {|byte| contents_hex << "0x#{byte.to_s(16)}" }

            "[ #{contents_hex.join(', ')} ]"
          end

          # Serializes the Rex::Java::Serialization::Model::BlockData
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