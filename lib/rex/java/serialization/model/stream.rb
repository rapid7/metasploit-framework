module Rex
  module Java
    module Serialization
      module Model
        # This class provides a Java Stream representation
        class Stream < Element

          include Rex::Java::Serialization::Model::Contents

          # @!attribute magic
          #   @return [Fixnum] The stream signature
          attr_accessor :magic
          # @!attribute version
          #   @return [Fixnum] The stream version
          attr_accessor :version
          # @!attribute contents
          #   @return [Array] The stream's contents
          attr_accessor :contents

          def initialize
            self.magic = STREAM_MAGIC
            self.version = STREAM_VERSION
            self.contents = []
          end

          # Deserializes a Java::Serialization::Model::Stream
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode(io)
            self.magic = decode_magic(io)
            self.version = decode_version(io)

            until io.eof?
              content = decode_content(io)
              self.contents << content
            end

            self
          end

          # Serializes the Java::Serialization::Model::Stream
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            encoded = ''
            encoded << [magic].pack('n')
            encoded << [version].pack('n')
            contents.each do |content|
              encoded << encode_content(content)
            end
            encoded
          end

          private

          # Deserializes the magic stream value
          #
          # @param io [IO] the io to read from
          # @return [String] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode_magic(io)
            magic = io.read(2)

            unless magic && magic.length == 2 && magic.unpack('n')[0] == STREAM_MAGIC
              raise ::RuntimeError, 'Failed to unserialize Stream'
            end

            STREAM_MAGIC
          end

          # Deserializes the version stream
          #
          # @param io [IO] the io to read from
          # @return [Fixnum] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed
          def decode_version(io)
            version = io.read(2)
            unless version && version.unpack('n')[0] == STREAM_VERSION
              raise ::RuntimeError, 'Failed to unserialize Stream'
            end

            STREAM_VERSION
          end
        end
      end
    end
  end
end