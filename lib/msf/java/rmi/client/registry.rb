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

          # Sends a Registry lookup call to the RMI endpoint
          #
          # @param opts [Hash]
          # @option opts [Rex::Socket::Tcp] :sock
          # @return [Hash, NilClass] The remote reference information if success, nil otherwise
          # @see Msf::Java::Rmi::Client::Registry::Builder.build_registry_lookup
          def send_registry_lookup(opts = {})
            send_call(
              sock: opts[:sock] || sock,
              call: build_registry_lookup(opts)
            )

            return_value = recv_return(
              sock: opts[:sock] || sock
            )

            remote_object = parse_registry_lookup(return_value)

            if remote_object.nil?
              return nil
            end

            remote_location = parse_registry_lookup_endpoint(return_value)

            if remote_location.nil?
              return nil
            end

            {object: remote_object}.merge(remote_location)
          end

          # Sends a Registry list call to the RMI endpoint
          #
          # @param opts [Hash]
          # @option opts [Rex::Socket::Tcp] :sock
          # @return [Array, NilClass] The set of names if success, nil otherwise
          # @see Msf::Java::Rmi::Client::Registry::Builder.build_registry_list
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
