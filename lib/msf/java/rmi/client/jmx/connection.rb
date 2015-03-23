# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Connection
          require 'msf/java/rmi/client/jmx/connection/builder'

          include Msf::Java::Rmi::Client::Jmx::Connection::Builder

          def send_jmx_get_object_instance(opts = {})
            send_call(
              sock: opts[:sock] || sock,
              call: build_jmx_get_object_instance(opts)
            )

            return_value = recv_return(
              sock: opts[:sock] || sock
            )

            if return_value.nil?
              return nil
            end

            if return_value.is_exception?
              raise ::Rex::Proto::Rmi::Exception, return_value.get_class_name
            end

            unless return_value.get_class_name == 'javax.management.ObjectInstance'
              return nil
            end

            true
          end

          def send_jmx_create_mbean(opts = {})
            send_call(
              sock: opts[:sock] || sock,
              call: build_jmx_create_mbean(opts)
            )

            return_value = recv_return(
              sock: opts[:sock] || sock
            )

            if return_value.nil?
              return nil
            end

            if return_value.is_exception?
              raise ::Rex::Proto::Rmi::Exception, return_value.get_class_name
            end

            unless return_value.get_class_name == 'javax.management.ObjectInstance'
              return nil
            end

            true
          end

          def send_jmx_invoke(opts = {})
            send_call(
              sock: opts[:sock] || sock,
              call: build_jmx_invoke(opts)
            )

            return_value = recv_return(
              sock: opts[:sock] || sock
            )

            if return_value.nil?
              return nil
            end

            if return_value.is_exception?
              raise ::Rex::Proto::Rmi::Exception, return_value.get_class_name
            end

            unless return_value.get_class_name == 'java.util.HashSet'
              return nil
            end

            true
          end
        end
      end
    end
  end
end
