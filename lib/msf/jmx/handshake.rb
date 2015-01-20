# -*- coding: binary -*-

module Msf
  module Jmx
    module Handshake
      def handshake_stream(id)
        block_data = Rex::Java::Serialization::Model::BlockData.new(nil, "#{id}\xff\xff\xff\xff\xf0\xe0\x74\xea\xad\x0c\xae\xa8")

        stream = Rex::Java::Serialization::Model::Stream.new
        stream.contents << block_data

        if jmx_role
          username = jmx_role
          password = jmx_password || ''

          stream.contents << auth_array_stream(username, password)
        else
          stream.contents << Rex::Java::Serialization::Model::NullReference.new
        end

        stream
      end

      def auth_array_stream(username, password)
        builder = Rex::Java::Serialization::Builder.new

        auth_array = builder.new_array(
          name: '[Ljava.lang.String;',
          serial: 0xadd256e7e91d7b47,
          values_type: 'java.lang.String;',
          values: [
            Rex::Java::Serialization::Model::Utf.new(nil, username),
            Rex::Java::Serialization::Model::Utf.new(nil, password)
          ]
        )

        auth_array
      end
    end
  end
end
