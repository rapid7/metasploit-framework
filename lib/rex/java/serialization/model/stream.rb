# -*- coding: binary -*-

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
          #   @return [Array] The stream contents
          attr_accessor :contents
          # @!attribute references
          #   @return [Array] The stream objects to be referenced through handles
          attr_accessor :references

          def initialize(stream = nil)
            super(nil)
            self.magic = STREAM_MAGIC
            self.version = STREAM_VERSION
            self.contents = []
            self.references = []
          end

          # Deserializes a Rex::Java::Serialization::Model::Stream
          #
          # @param io [IO] the io to read from
          # @return [self] if deserialization succeeds
          # @raise [Rex::Java::Serialization::DecodeError] if deserialization doesn't succeed
          def decode(io)
            self.magic = decode_magic(io)
            self.version = decode_version(io)

            until io.eof?
              content = decode_content(io, self)
              self.contents << content
            end

            self
          end

          # Serializes the Rex::Java::Serialization::Model::Stream
          #
          # @return [String] if serialization succeeds
          # @raise [Rex::Java::Serialization::EncodeError] if serialization doesn't succeed
          def encode
            encoded = ''
            encoded << [magic].pack('n')
            encoded << [version].pack('n')
            contents.each do |content|
              encoded << encode_content(content)
            end
            encoded
          end

          # Adds an element to the references array
          #
          # @param ref [Rex::Java::Serialization::Model::Element] the object to save as reference dst
          def add_reference(ref)
            self.references.push(ref)
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            str = "@magic: 0x#{magic.to_s(16)}\n"
            str << "@version: #{version}\n"
            str << "@contents: [\n"
            contents.each do |content|
              str << "  #{print_content(content)}\n"
            end
            str << "]\n"
            str << "@references: [\n"
            references.each do |ref|
                str << "  [#{(references.index(ref) + BASE_WIRE_HANDLE).to_s(16)}] #{print_content(ref)}\n"
            end
            str << "]\n"
          end

          private

          # Deserializes the magic stream value
          #
          # @param io [IO] the io to read from
          # @return [String] if deserialization succeeds
          # @raise [Rex::Java::Serialization::DecodeError] if deserialization doesn't succeed
          def decode_magic(io)
            magic = io.read(2)

            unless magic && magic.length == 2 && magic.unpack('n')[0] == STREAM_MAGIC
              raise Rex::Java::Serialization::DecodeError, 'Failed to unserialize Stream'
            end

            STREAM_MAGIC
          end

          # Deserializes the version stream
          #
          # @param io [IO] the io to read from
          # @return [Fixnum] if deserialization succeeds
          # @raise [Rex::Java::Serialization::DecodeError] if deserialization doesn't succeed
          def decode_version(io)
            version = io.read(2)
            unless version && version.unpack('n')[0] == STREAM_VERSION
              raise Rex::Java::Serialization::DecodeError, 'Failed to unserialize Stream'
            end

            STREAM_VERSION
          end
        end
      end
    end
  end
end