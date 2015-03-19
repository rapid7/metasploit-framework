# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Registry
          module Parser

            # Parses a java.rmi.registry.Registry.lookup() return value to find out
            # the remote object bound.
            #
            # @param return_value [Rex::Java::Serialization::Model::ReturnValue]
            # @return [String, NilClass] The remote object name if success, nil otherwise
            def parse_registry_lookup(return_value)
              if return_value.nil? || return_value.is_exception?
                return nil
              end

              unless return_value.value[0].is_a?(Rex::Java::Serialization::Model::NewObject)
                return nil
              end

              case return_value.value[0].class_desc.description
              when Rex::Java::Serialization::Model::NewClassDesc
                return return_value.value[0].class_desc.description.class_name.contents
              when Rex::Java::Serialization::Model::ProxyClassDesc
                return return_value.value[0].class_desc.description.interfaces[0].contents
              else
                return nil
              end
            end

            # Parses a java.rmi.registry.Registry.lookup() return value to find out
            # the remote reference information.
            #
            # @param return_value [Rex::Java::Serialization::Model::ReturnValue]
            # @return [Hash, NilClass] The remote interface information if success, nil otherwise
            def parse_registry_lookup_endpoint(return_value)
              if return_value.nil? || return_value.is_exception?
                return nil
              end

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

            # Parses a java.rmi.registry.Registry.list() return value to find out
            # the list of names registered.
            #
            # @param return_value [Rex::Java::Serialization::Model::ReturnValue]
            # @return [Array, NilClass] The list of names registered if success, nil otherwise
            def parse_registry_list(return_value)
              if return_value.nil? || return_value.is_exception?
                return nil
              end

              unless return_value.value[0].is_a?(Rex::Java::Serialization::Model::NewArray)
                return nil
              end

              unless return_value.value[0].type == 'java.lang.String;'
                return nil
              end

              return_value.value[0].values.collect { |val| val.contents }
            end
          end
        end
      end
    end
  end
end
