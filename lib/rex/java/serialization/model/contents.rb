module Rex
  module Java
    module Serialization
      module Model
        module Contents
          include Rex::Java::Serialization

          # Deserializes a content
          #
          # @param io [IO] the io to read from
          # @return [Rex::Java::Serialization::Model::Element] if deserialization succeeds
          # @raise [RuntimeError] if deserialization doesn't succeed or unsupported content
          def decode_content(io, stream)
            opcode = io.read(1)
            raise ::RuntimeError, 'Failed to unserialize content' if opcode.nil?
            opcode = opcode.unpack('C')[0]
            content = nil

            case opcode
            when TC_BLOCKDATA
              content = BlockData.decode(io, stream)
            when TC_BLOCKDATALONG
              content = BlockDataLong.decode(io, stream)
            when TC_ENDBLOCKDATA
              content = EndBlockData.decode(io, stream)
            when TC_OBJECT
              content = NewObject.decode(io, stream)
            when TC_CLASS
              content = ClassDesc.decode(io, stream)
            when TC_ARRAY
              content = NewArray.decode(io, stream)
            when TC_STRING
              content = Utf.decode(io, stream)
              stream.add_reference(content) unless stream.nil?
            when TC_LONGSTRING
              content = LongUtf.decode(io, stream)
              stream.add_reference(content) unless stream.nil?
            when TC_ENUM
              content = NewEnum.decode(io, stream)
            when TC_CLASSDESC
              content = NewClassDesc.decode(io, stream)
            when TC_PROXYCLASSDESC
              raise ::RuntimeError, 'Failed to unserialize unsupported TC_PROXYCLASSDESC content'
            when TC_REFERENCE
              content = Reference.decode(io, stream)
            when TC_NULL
              content = NullReference.decode(io, stream)
            when TC_EXCEPTION
              raise ::RuntimeError, 'Failed to unserialize unsupported TC_EXCEPTION content'
            when TC_RESET
              content = Reset.decode(io, stream)
            else
              raise ::RuntimeError, 'Failed to unserialize content'
            end

            content
          end

          # Serializes a content
          #
          # @param content [Rex::Java::Serialization::Model::Element] the content to serialize
          # @return [String] if serialization succeeds
          # @raise [RuntimeError] if serialization doesn't succeed
          def encode_content(content)
            encoded = ''

            case content
            when BlockData
              encoded << [TC_BLOCKDATA].pack('C')
            when BlockDataLong
              encoded << [TC_BLOCKDATALONG].pack('C')
            when EndBlockData
              encoded << [TC_ENDBLOCKDATA].pack('C')
            when NewObject
              encoded << [TC_OBJECT].pack('C')
            when ClassDesc
              encoded << [TC_CLASS].pack('C')
            when NewArray
              encoded << [TC_ARRAY].pack('C')
            when Utf
              encoded << [TC_STRING].pack('C')
            when LongUtf
              encoded << [TC_LONGSTRING].pack('C')
            when NewEnum
              encoded << [TC_ENUM].pack('C')
            when NewClassDesc
              encoded << [TC_CLASSDESC].pack('C')
            when NullReference
              encoded << [TC_NULL].pack('C')
            when Reset
              encoded << [TC_RESET].pack('C')
            when Reference
              encoded << [TC_REFERENCE].pack('C')
            else
              raise ::RuntimeError, 'Failed to serialize content'
            end

            encoded << content.encode
            encoded
          end
        end
      end
    end
  end
end