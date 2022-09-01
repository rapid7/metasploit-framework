# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        # This class provides a representation of an RMI return value
        class CallData < Element

          # @!attribute object_number
          #   @return [Integer] Random to identify the object being called
          attr_accessor :object_number
          # @!attribute uid
          #   @return [Rex::Proto::Rmi::Model::UniqueIdentifier] unique identifier for the target to call
          attr_accessor :uid
          # @!attribute operation
          #   @return [Integer] On JDK 1.1 stub protocol the operation index in the interface. On JDK 1.2
          #     it is -1.
          attr_accessor :operation
          # @!attribute hash
          #   @return [Integer] On JDK 1.1 stub protocol the stub's interface hash. On JDK1.2 is a hash
          #     representing the method to call.
          attr_accessor :hash
          # @!attribute arguments
          #   @return [Array] the returned exception or value according to code
          attr_accessor :arguments

          # Encodes the Rex::Proto::Rmi::Model::CallData into an String.
          #
          # @return [String]
          def encode
            stream = Rex::Java::Serialization::Model::Stream.new
            block_data = Rex::Java::Serialization::Model::BlockData.new(nil, encode_object_number + encode_uid + encode_operation + encode_hash)

            stream.contents << block_data
            stream.contents += arguments

            stream.encode
          end

          # Decodes the Rex::Proto::Rmi::Model::CallData from the input.
          #
          # @param io [IO] the IO to read from
          # @return [Rex::Proto::Rmi::Model::CallData]
          def decode(io)
            stream = Rex::Java::Serialization::Model::Stream.decode(io)

            block_data = stream.contents[0]
            block_data_io = StringIO.new(block_data.contents, 'rb')

            self.object_number = decode_object_number(block_data_io)
            self.uid = decode_uid(block_data_io)
            self.operation = decode_operation(block_data_io)
            self.hash = decode_hash(block_data_io)
            self.arguments = []

            stream.contents[1..stream.contents.length - 1].each do |content|
              self.arguments << content
            end

            self
          end

          private

          # Reads the object number from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          def decode_object_number(io)
            object_number = read_long(io)

            object_number
          end

          # Reads and deserializes the uid from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Rex::Proto::Rmi::Model::UniqueIdentifier]
          def decode_uid(io)
            uid = Rex::Proto::Rmi::Model::UniqueIdentifier.decode(io)

            uid
          end

          # Reads the operation from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          def decode_operation(io)
            operation = read_int(io)

            operation
          end

          # Reads the hash from the IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          def decode_hash(io)
            hash = read_long(io)

            hash
          end

          # Encodes the code field
          #
          # @return [String]
          def encode_object_number
            [object_number].pack('q>')
          end

          # Encodes the uid field
          #
          # @return [String]
          def encode_uid
            uid.encode
          end

          # Encodes the operation field
          #
          # @return [String]
          def encode_operation
            [operation].pack('l>')
          end

          # Encodes the hash field
          #
          # @return [String]
          def encode_hash
            [hash].pack('q>')
          end
        end
      end
    end
  end
end