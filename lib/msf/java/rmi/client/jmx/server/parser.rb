# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Jmx
          module Server
            module Parser

              # Parses a java.rmi.registry.Registry.lookup() return value to find out
              # the remote object bound.
              #
              # @param return_value [Rex::Proto::Rmi::Model::ReturnValue]
              # @return [String, NilClass] The remote object name if success, nil otherwise
              def parse_jmx_new_client(return_value)
                return_object = ''

                case return_value.value[0].class_desc.description
                when Rex::Java::Serialization::Model::NewClassDesc
                  return_object = return_value.value[0].class_desc.description.class_name.contents
                when Rex::Java::Serialization::Model::ProxyClassDesc
                  return_object = return_value.value[0].class_desc.description.interfaces[0].contents
                else
                  return nil
                end

                unless return_object == 'javax.management.remote.rmi.RMIConnectionImpl_Stub'
                  return nil
                end

                ref = parse_jmx_new_client_endpoint(return_value)

                ref
              end

              # Parses a java.rmi.registry.Registry.lookup() return value to find out
              # the remote reference information.
              #
              # @param return_value [Rex::Java::Serialization::Model::ReturnValue]
              # @return [Hash, NilClass] The remote interface information if success, nil otherwise
              def parse_jmx_new_client_endpoint(return_value)
                values_size = return_value.value.length
                end_point_block_data = return_value.value[values_size - 2]
                unless end_point_block_data.is_a?(Rex::Java::Serialization::Model::BlockData)
                  return nil
                end

                return_io = StringIO.new(end_point_block_data.contents, 'rb')

                ref = extract_string(return_io)
                unless ref && ref == 'UnicastRef'
                  return nil
                end

                address = extract_string(return_io)
                return nil unless address

                port = extract_int(return_io)
                return nil unless port

                object_number = extract_long(return_io)

                uid = Rex::Proto::Rmi::Model::UniqueIdentifier.decode(return_io)

                {address: address, port: port, object_number: object_number, uid: uid}
              end
            end
          end
        end
      end
    end
  end
end
