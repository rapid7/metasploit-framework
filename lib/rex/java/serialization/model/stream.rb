module Rex
  module Java
    module Serialization
      module Model
        # This class provides a NewEnum (Java Enum) representation
        class Stream < Element

          include Rex::Java::Serialization

          # @!attribute magic
          #   @return [String] The description of the enum
          attr_accessor :magic
          # @!attribute version
          #   @return [Fixnum] The description of the enum
          attr_accessor :version
          # @!attribute contents
          #   @return [Array] The constant value in the Java Enum
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
            self.constant_name = decode_version(io)

            self.contents << Content.decode until io.eof?

            self
          end

          # Serializes the Java::Serialization::Model::Stream
          #
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode
            encoded = ''
            encoded << magic
            encoded << [version].pack('n')
            contents.each do |content|
              encoded << content.encode
            end
            encoded
          end

          private

          # Deserializes the magic stream value
          #
          # @param io [IO] the io to read from
          # @return [String] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succed
          def decode_magic(io)
            magic = io.read(2)
            unless magic && magic == STREAM_MAGIC
              raise ::RuntimeError, 'Failed to unserialize Stream'
            end

            magic
          end

          # Deserializes the version stream
          #
          # @param io [IO] the io to read from
          # @return [Fixnum] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succed
          def decode_version(io)
            version = io.read(2)
            unless version && version.unpack('n')[0] == STREAM_VERSION
              raise ::RuntimeError, 'Failed to unserialize Stream'
            end

            version
          end
        end
      end
    end
  end
end