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
    end
  end
end
