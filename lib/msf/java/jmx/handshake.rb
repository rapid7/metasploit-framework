# -*- coding: binary -*-

module Msf
  module Java
    module Jmx
      # This module provides methods which help to handle a JMX handshake
      module Handshake

        # Builds a Rex::Java::Serialization::Model::Stream to make
        # a JMX handshake with an endpoint
        #
        # @param id [String] The endpoint UnicastRef ObjId
        # @return [Rex::Java::Serialization::Model::Stream]
        def handshake_stream(obj_id)
          block_data = Rex::Java::Serialization::Model::BlockData.new(nil, "#{obj_id}\xff\xff\xff\xff\xf0\xe0\x74\xea\xad\x0c\xae\xa8")

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

        # Builds a Rex::Java::Serialization::Model::NewArray with credentials
        # to make an authenticated handshake
        #
        # @param username [String] The username (role) to authenticate with
        # @param password [String] The password to authenticate with
        # @return [Rex::Java::Serialization::Model::NewArray]
        def auth_array_stream(username, password)
          builder = Rex::Java::Serialization::Builder.new

          auth_array = builder.new_array(
            name: '[Ljava.lang.String;',
            serial: 0xadd256e7e91d7b47, # serialVersionUID
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
end
