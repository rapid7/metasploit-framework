# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Registry
          require 'msf/java/rmi/client/registry/builder'
          require 'msf/java/rmi/client/registry/parser'

          include Msf::Java::Rmi::Client::Registry::Builder
          include Msf::Java::Rmi::Client::Registry::Parser

          def send_registry_lookup(opts = {})
            send_call(
              sock: opts[:sock] || sock,
              call: build_registry_lookup(opts)
            )

            return_value = recv_return(
              sock: opts[:sock] || sock
            )

            remote_stub = parse_registry_lookup(return_value)

            remote_stub
          end

          def send_registry_list(opts = {})
            send_call(
              sock: opts[:sock] || sock,
              call: build_registry_list(opts)
            )

            return_value = recv_return(
              sock: opts[:sock] || sock
            )

            names = parse_registry_list(return_value)

            names
          end
        end
      end
    end
  end
end
