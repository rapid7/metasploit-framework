# -*- coding: binary -*-

module Msf
  module Jmx
    module Discovery
      def build_discovery
        stream = Rex::Java::Serialization::Model::Stream.new

        block_data = Rex::Java::Serialization::Model::BlockData.new
        block_data.contents = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        block_data.contents << "\x00\x00\x00\x02\x44\x15\x4d\xc9\xd4\xe6\x3b\xdf"
        block_data.length = block_data.contents.length

        stream.contents << block_data

        stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, 'jmxrmi')

        stream
      end

      def extract_mbean_server(stream)
        my_block = false
        stub = false
        i = 0
        stub_index = 0
        stream.contents.each do |content|
          if content.class == Rex::Java::Serialization::Model::BlockData && i == 0
            my_block = true
          end

          if content.class == Rex::Java::Serialization::Model::NewObject && content.class_desc.description.class_name.contents == 'javax.management.remote.rmi.RMIServerImpl_Stub'
            stub = true
            stub_index = i
            break
          end
          i = i + 1
        end

        unless my_block && stub
          return nil
        end

        my_block_id = stream.contents[0].contents[1..-1]

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

        { address: address, port: port, id: id, my_id: my_block_id }
      end
    end
  end
end
