# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Jmx
          module Connection
            module Builder
              # Builds an RMI call to java.rmi.registry.Registry.lookup() used to
              # retrieve the remote reference bound to a name.
              #
              # @param opts [Hash]
              # @option opts [String] :name the name to lookup
              # @return [Rex::Proto::Rmi::Model::Call]
              # @see Msf::Java::Rmi::Builder.build_call
              def build_jmx_get_object_instance(opts = {})
                object_number = opts[:object_number] || 0
                uid_number = opts[:uid_number] || 0
                uid_time = opts[:uid_time] || 0
                uid_count = opts[:uid_count] || 0
                name = opts[:name] || ''

                arguments = build_jmx_get_object_instance_args(name)

                call = build_call(
                  object_number: object_number,
                  uid_number: uid_number,
                  uid_time: uid_time,
                  uid_count: uid_count,
                  operation: -1,
                  hash: 6950095694996159938, # RMIConnectionImpl_Stub.getObjectInstance()
                  arguments: arguments
                )

                call
              end

              # javax.management.ObjectName $param_ObjectName_1, javax.security.auth.Subject $param_Subject_2
              def build_jmx_get_object_instance_args(name = '')
                builder = Rex::Java::Serialization::Builder.new

                new_object = builder.new_object(
                  name: 'javax.management.ObjectName',
                  serial: 0xf03a71beb6d15cf, # serialVersionUID
                  flags: 3
                )

                arguments = [
                  new_object,
                  Rex::Java::Serialization::Model::Utf.new(nil, name),
                  Rex::Java::Serialization::Model::EndBlockData.new,
                  Rex::Java::Serialization::Model::NullReference.new
                ]

                arguments
              end


              #// implementation of createMBean(String, ObjectName, Subject)
              #public javax.management.ObjectInstance createMBean(java.lang.String $param_String_1, javax.management.ObjectName $param_ObjectName_2, javax.security.auth.Subject $param_Subject_3)
              def build_jmx_create_mbean(opts = {})
                name = opts[:name] || ''
                object_number = opts[:object_number] || 0
                uid_number = opts[:uid_number] || 0
                uid_time = opts[:uid_time] || 0
                uid_count = opts[:uid_count] || 0

                arguments = build_jmx_create_mbean_args(name)

                call = build_call(
                  object_number: object_number,
                  uid_number: uid_number,
                  uid_time: uid_time,
                  uid_count: uid_count,
                  operation: -1,
                  hash: 2510753813974665446,
                  arguments: arguments
                )

                call
              end

              #(String, ObjectName, Subject)
              def build_jmx_create_mbean_args(name = '')
                arguments = [
                  Rex::Java::Serialization::Model::Utf.new(nil, name),
                  Rex::Java::Serialization::Model::NullReference.new,
                  Rex::Java::Serialization::Model::NullReference.new
                ]

                arguments
              end
            end


            #implementation of invoke(ObjectName, String, MarshalledObject, String[], Subject)
            #public java.lang.Object invoke(javax.management.ObjectName $param_ObjectName_1, java.lang.String $param_String_2, java.rmi.MarshalledObject $param_MarshalledObject_3, java.lang.String[] $param_arrayOf_String_4, javax.security.auth.Subject $param_Subject_5)            def build_jmx_invoke(opts = {})
            def build_jmx_invoke(opts = {})
              object_number = opts[:object_number] || 0
              uid_number = opts[:uid_number] || 0
              uid_time = opts[:uid_time] || 0
              uid_count = opts[:uid_count] || 0

              arguments = build_jmx_invoke_args(opts)

              call = build_call(
                object_number: object_number,
                uid_number: uid_number,
                uid_time: uid_time,
                uid_count: uid_count,
                operation: -1,
                hash: 1434350937885235744,
                arguments: arguments
              )

              call
            end

            #(ObjectName, String, MarshalledObject, String[], Subject)
            def build_jmx_invoke_args(opts = {})
              object_name = opts[:object] || ''
              method_name = opts[:method] || ''
              args = opts[:args] || {}

              builder = Rex::Java::Serialization::Builder.new

              new_object = builder.new_object(
                name: 'javax.management.ObjectName',
                serial: 0xf03a71beb6d15cf, # serialVersionUID
                flags: 3
              )

              data_binary = builder.new_array(
                name: '[B',
                serial: 0xacf317f8060854e0, # serialVersionUID
                values_type: 'byte',
                values: build_invoke_arguments_obj_bytes(args).encode.unpack('C*')
              )

              marshall_object = builder.new_object(
                name: 'java.rmi.MarshalledObject',
                serial: 0x7cbd1e97ed63fc3e, # serialVersionUID
                fields: [
                        ['int', 'hash'],
                        ['array', 'locBytes', '[B'],
                        ['array', 'objBytes', '[B']
                      ],
                data: [
                        ["int", 1919492550],
                        Rex::Java::Serialization::Model::NullReference.new,
                        data_binary
                      ]
              )

              new_array = builder.new_array(
                name: '[Ljava.lang.String;',
                serial: 0xadd256e7e91d7b47, # serialVersionUID
                values_type: 'java.lang.String;',
                values: args.keys.collect { |k| Rex::Java::Serialization::Model::Utf.new(nil, k) }
              )

              arguments = [
                new_object,
                Rex::Java::Serialization::Model::Utf.new(nil, object_name),
                Rex::Java::Serialization::Model::EndBlockData.new,
                Rex::Java::Serialization::Model::Utf.new(nil, method_name),
                marshall_object,
                new_array,
                Rex::Java::Serialization::Model::NullReference.new
              ]

              arguments
            end

            # Builds a Rex::Java::Serialization::Model::Stream with the arguments to
            # simulate a call to the Java invoke method method.
            #
            # @param args [Hash] the arguments of the method to invoke
            # @return [Rex::Java::Serialization::Model::Stream]
            def build_invoke_arguments_obj_bytes(args = {})
              builder = Rex::Java::Serialization::Builder.new

              new_array = builder.new_array(
                name: '[Ljava.lang.Object;',
                serial: 0x90ce589f1073296c, # serialVersionUID
                annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
                values_type: 'java.lang.Object;',
                values: args.values.collect { |arg| Rex::Java::Serialization::Model::Utf.new(nil, arg) }
              )

              stream = Rex::Java::Serialization::Model::Stream.new
              stream.contents << new_array

              stream
            end

          end
        end
      end
    end
  end
end
