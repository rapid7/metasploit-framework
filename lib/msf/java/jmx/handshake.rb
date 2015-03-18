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
        def handshake_stream(opts = {})
          object_number = opts[:object_number] || 0
          uid_number = opts[:uid_number] || 0
          uid_time = opts[:uid_time] || 0
          uid_count = opts[:uid_count] || 0

          arguments = []
          if jmx_role
            username = jmx_role
            password = jmx_password || ''
            arguments << auth_array_stream(username, password)
          else
            arguments << Rex::Java::Serialization::Model::NullReference.new
          end

          call = build_call(
            object_number: object_number,
            uid_number: uid_number,
            uid_time: uid_time,
            uid_count: uid_count,
            operation: -1,
            hash: -1089742558549201240,
            arguments: arguments
          )

          call
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
