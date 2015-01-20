# -*- coding: binary -*-

module Msf
  module Jmx
    module Discovery
      def discovery_stream
        block_data = Rex::Java::Serialization::Model::BlockData.new(
          nil,
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
              "\x00\x00\x00\x02\x44\x15\x4d\xc9\xd4\xe6\x3b\xdf"
        )

        stream = Rex::Java::Serialization::Model::Stream.new
        stream.contents << block_data
        stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, 'jmxrmi')

        stream
      end

      def extract_mbean_server(block_data)
        data_io = StringIO.new(block_data.contents)

        ref = extract_string(data_io)
        unless ref && ref == 'UnicastRef'
          return nil
        end

        address = extract_string(data_io)
        return nil unless address

        port = extract_int(data_io)
        return nil unless port

        id = data_io.read

        { address: address, port: port, id: id }
      end
    end
  end
end
