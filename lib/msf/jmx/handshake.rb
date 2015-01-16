# -*- coding: binary -*-

module Msf
  module Jmx
    module Handshake
      def handshake_stream(id)
        stream = Rex::Java::Serialization::Model::Stream.new

        block_data = Rex::Java::Serialization::Model::BlockData.new
        block_data.contents = id + "\xff\xff\xff\xff\xf0\xe0\x74\xea\xad\x0c\xae\xa8"
        block_data.length = block_data.contents.length

        stream.contents << block_data

        if datastore['USERNAME']
          username = datastore['USERNAME']
          password = datastore['PASSWORD'] || ''

          stream.contents << auth_array_stream(username, password)
        else
          stream.contents << Rex::Java::Serialization::Model::NullReference.new
        end

        stream
      end

      def auth_array_stream(username, password)
        auth_array_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
        auth_array_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, '[Ljava.lang.String;')
        auth_array_class_desc.serial_version = 0xadd256e7e91d7b47
        auth_array_class_desc.flags = 2
        auth_array_class_desc.fields = []
        auth_array_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
        auth_array_class_desc.class_annotation.contents = [
            Rex::Java::Serialization::Model::NullReference.new,
            Rex::Java::Serialization::Model::EndBlockData.new
        ]
        auth_array_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
        auth_array_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

        auth_array = Rex::Java::Serialization::Model::NewArray.new
        auth_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
        auth_array.array_description.description = auth_array_class_desc
        auth_array.type = 'java.lang.String;'
        auth_array.values = [
            Rex::Java::Serialization::Model::Utf.new(nil, username),
            Rex::Java::Serialization::Model::Utf.new(nil, password)
        ]

        auth_array
      end

      def extract_rmi_connection_stub(stream)
        stub = false
        stub_index = 0
        stream.contents.each do |content|
          if content.class == Rex::Java::Serialization::Model::NewObject && content.class_desc.description.class_name.contents == 'javax.management.remote.rmi.RMIConnectionImpl_Stub'
            stub = true
            break
          end
          stub_index = stub_index + 1
        end

        unless stub
          return nil
        end

        block_data = stream.contents[stub_index + 1]
        data_io = StringIO.new(block_data.contents)

        ref_length = data_io.read(2)
        unless ref_length && ref_length.length == 2
          return nil
        end
        ref_length = ref_length.unpack('n')[0]

        ref = data_io.read(ref_length)
        unless ref && ref.length == ref_length && ref == 'UnicastRef'
          return nil
        end

        address_length = data_io.read(2)
        unless address_length && address_length.length == 2
          return nil
        end
        address_length = address_length.unpack('n')[0]

        address = data_io.read(address_length)
        unless address && address.length == address_length
          return nil
        end

        port = data_io.read(4)
        unless port && port.length == 4
          return nil
        end
        port = port.unpack('N')[0]

        id = data_io.read

        { address: address, port: port, :id => id }
      end
    end
  end
end
