# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Registry
          module Builder
            def build_registry_lookup(opts = {})
              object_number = opts[:object_number] || 0
              uid_number = opts[:uid_number] || 0
              uid_time = opts[:uid_time] || 0
              uid_count = opts[:uid_count] || 0
              name = opts[:name] || ''

              call = build_call(
                object_number: object_number,
                uid_number: uid_number,
                uid_time: uid_time,
                uid_count: uid_count,
                operation: 2, # java.rmi.Remote lookup(java.lang.String)
                hash: 0x44154dc9d4e63bdf, # RegistryImpl_Stub
                arguments: [Rex::Java::Serialization::Model::Utf.new(nil, name)]
              )

              call
            end

            def build_registry_list(opts = {})
              object_number = opts[:object_number] || 0
              uid_number = opts[:uid_number] || 0
              uid_time = opts[:uid_time] || 0
              uid_count = opts[:uid_count] || 0

              call = build_call(
                object_number: object_number,
                uid_number: uid_number,
                uid_time: uid_time,
                uid_count: uid_count,
                operation: 1, # java.lang.String list()[]
                hash: 0x44154dc9d4e63bdf, # RegistryImpl_Stub
                arguments: []
              )

              call
            end
          end
        end
      end
    end
  end
end
