# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Jmx
          module Connection
            module Parser
              def parse_jmx_get_object_instance(return_value)
                if return_value.nil? || return_value.is_exception?
                  puts "is exception :?"
                  puts  "#{return_value.value[0].class}"
                  puts "#{return_value.value[0].class_desc.description.class_name.contents}"
                  return nil
                end

                puts  "#{return_value.value[0].class}"

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
            end
          end
        end
      end
    end
  end
end
