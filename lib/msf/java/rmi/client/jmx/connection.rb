# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Registry
          require 'msf/java/rmi/client/jmx/connection/builder'
          require 'msf/java/rmi/client/jmx/connection/parser'

          include Msf::Java::Rmi::Client::Jmx::Connection::Builder
          include Msf::Java::Rmi::Client::Jmx::Connection::Parser

          def send_jmx_get_object_instance(opts = {})
            send_call(
              sock: opts[:sock] || sock,
              call: build_jmx_get_object_instance(opts)
            )

            return_value = recv_return(
              sock: opts[:sock] || sock
            )

            return_value
            #remote_object = parse_jmx_get_object_instance(return_value)

            #remote_object
          end
        end

        def send_jmx_create_mbean(opts = {})
          send_call(
            sock: opts[:sock] || sock,
            call: build_jmx_create_mbean(opts)
          )

          return_value = recv_return(
            sock: opts[:sock] || sock
          )

          return_value
          #remote_object = parse_jmx_get_object_instance(return_value)

          #remote_object
        end

        def send_jmx_invoke(opts = {})
          send_call(
            sock: opts[:sock] || sock,
            call: build_jmx_invoke(opts)
          )

          return_value = recv_return(
            sock: opts[:sock] || sock
          )

          return_value
        end
      end
    end
  end
end
