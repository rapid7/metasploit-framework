# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI return value
        class ReturnValue < Element

          # @!attribute code
          #   @return [Integer] the return code
          attr_accessor :code
          # @!attribute uid
          #   @return [Rex::Proto::Rmi::Model::UniqueIdentifier] unique identifier of the returned value
          attr_accessor :uid
          # @!attribute value
          #   @return [Array] the returned exception or value according to code
          attr_accessor :value

          # Encodes the Rex::Proto::Rmi::Model::ReturnValue into an String.
          #
          # @return [String]
          def encode
            stream = Rex::Java::Serialization::Model::Stream.new
            block_data = Rex::Java::Serialization::Model::BlockData.new(nil, encode_code + encode_uid)

            stream.contents << block_data
            value.each do |v|
              stream.contents << v
            end

            stream.encode
          end

          # Decodes the Rex::Proto::Rmi::Model::ReturnValue from the input.
          #
          # @param io [IO] the IO to read from
          # @return [Rex::Proto::Rmi::Model::ReturnValue]
          def decode(io)
            stream = Rex::Java::Serialization::Model::Stream.decode(io)

            block_data = stream.contents[0]
            block_data_io = StringIO.new(block_data.contents, 'rb')

            self.code = decode_code(block_data_io)
            self.uid = decode_uid(block_data_io)
            self.value = []

            stream.contents[1..stream.contents.length - 1].each do |content|
              self.value << content
            end

            self
          end

          # Answers if the ReturnValue is an exception
          #
          # @return [Boolean]
          def is_exception?
            code == RETURN_EXCEPTION
          end

          # The object/exception class of the returned value
          #
          # @return [String, NilClass] the returned value class, nil it cannot be retrieved
          def get_class_name
            unless value[0] && value[0].is_a?(Rex::Java::Serialization::Model::NewObject)
              return nil
            end

            case value[0].class_desc.description
            when Rex::Java::Serialization::Model::NewClassDesc
              return value[0].class_desc.description.class_name.contents
            when Rex::Java::Serialization::Model::ProxyClassDesc
              return value[0].class_desc.description.interfaces[0].contents
            else
              return nil
            end
          end

          private

          # Reads the return code from the IO
          #
          # @param io [IO] the IO to read from
          # @return [String]
          # @raise [Rex::Proto::Rmi::DecodeError] if fails to decode the return code
          def decode_code(io)
            code = read_byte(io)
            unless code == RETURN_VALUE || code == RETURN_EXCEPTION
              raise Rex::Proto::Rmi::DecodeError, 'Failed to decode the ReturnValue code'
            end

            code
          end

          # Reads and deserializes the uid from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Rex::Proto::Rmi::Model::UniqueIdentifier]
          def decode_uid(io)
            uid = Rex::Proto::Rmi::Model::UniqueIdentifier.decode(io)

            uid
          end

          # Encodes the code field
          #
          # @return [String]
          def encode_code
            [code].pack('c')
          end

          # Encodes the uid field
          #
          # @return [String]
          def encode_uid
            uid.encode
          end
        end
      end
    end
  end
end