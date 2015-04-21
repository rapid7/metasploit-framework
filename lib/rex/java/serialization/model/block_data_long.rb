# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        # This class provides a block data (long) representation
        class BlockDataLong < Element

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

          # Deserializes a Rex::Java::Serialization::Model::BlockDataLong
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [Rex::Java::Serialization::DecodeError] if deserialization doesn't succeed
          def decode(io)
            raw_length = io.read(4)
            if raw_length.nil? || raw_length.length != 4
              raise Rex::Java::Serialization::DecodeError, 'Failed to unserialize BlockDataLong'
            end
            self.length = raw_length.unpack('N')[0]

            if length == 0
              self.contents = ''
            else
              self.contents = io.read(length)
              if contents.nil? || contents.length != length
                raise Rex::Java::Serialization::DecodeError, 'Failed to unserialize BlockData'
              end
            end

            self
          end

          # Serializes the Rex::Java::Serialization::Model::BlockDataLong
          #
          # @return [String]
          def encode
            encoded = [length].pack('N')
            encoded << contents

            encoded
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            contents_hex = []
            contents.each_byte {|byte| contents_hex << "0x#{byte.to_s(16)}" }

            "[ #{contents_hex.join(', ')} ]"
          end
        end
      end
    end
  end
end