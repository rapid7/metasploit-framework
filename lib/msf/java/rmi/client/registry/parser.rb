# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Registry
          module Parser
            def parse_registry_lookup(return_value)
              if return_value.nil? || return_value.is_exception?
                return nil
              end

              unless return_value.value[0].is_a?(Rex::Java::Serialization::Model::NewObject)
                return nil
              end

              return_value.value[0].class_desc.description.class_name.contents
            end

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
