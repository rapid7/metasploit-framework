# -*- coding: binary -*-

module Msf
  module Java
    module Jmx
      module Mbean
        # This module provides methods which help to handle with MBean related calls.
        # Specially, simulating calls with the Java javax.management.MBeanServerConnection
        # class
        module ServerConnection

          # Builds a Rex::Java::Serialization::Model::Stream to simulate a call
          # to the createMBean method.
          #
          # @param opts [Hash{Symbol => String}]
          # @option opts [String] :obj_id the jmx endpoint ObjId
          # @option opts [String] :name the name of the MBean
          # @return [Rex::Java::Serialization::Model::Stream]
          def create_mbean_stream(opts = {})
            obj_id = opts[:obj_id] || "\x00" * 22
            name = opts[:name] || ''
            block_data = Rex::Java::Serialization::Model::BlockData.new(nil, "#{obj_id}\xff\xff\xff\xff\x22\xd7\xfd\x4a\x90\x6a\xc8\xe6")

            stream = Rex::Java::Serialization::Model::Stream.new
            stream.contents << block_data
            stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, name)
            stream.contents << Rex::Java::Serialization::Model::NullReference.new
            stream.contents << Rex::Java::Serialization::Model::NullReference.new

            stream
          end

          # Builds a Rex::Java::Serialization::Model::Stream to simulate a call to the
          # Java getObjectInstance method.
          #
          # @param opts [Hash{Symbol => String}]
          # @option opts [String] :obj_id the jmx endpoint ObjId
          # @option opts [String] :name the name of the MBean
          # @return [Rex::Java::Serialization::Model::Stream]
          def get_object_instance_stream(opts = {})
            obj_id = opts[:obj_id] || "\x00" * 22
            name = opts[:name] || ''

            builder = Rex::Java::Serialization::Builder.new

            block_data = Rex::Java::Serialization::Model::BlockData.new(nil, "#{obj_id}\xff\xff\xff\xff\x60\x73\xb3\x36\x1f\x37\xbd\xc2")

            new_object = builder.new_object(
              name: 'javax.management.ObjectName',
              serial: 0xf03a71beb6d15cf, # serialVersionUID
              flags: 3
            )

            stream = Rex::Java::Serialization::Model::Stream.new
            stream.contents << block_data
            stream.contents << new_object
            stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, name)
            stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
            stream.contents << Rex::Java::Serialization::Model::NullReference.new

            stream
          end

          # Builds a Rex::Java::Serialization::Model::Stream to simulate a call
          # to the Java invoke method.
          #
          # @param opts [Hash{Symbol => String}]
          # @option opts [String] :obj_id the jmx endpoint ObjId
          # @option opts [String] :object the object whose method we want to call
          # @option opts [String] :method the method name to invoke
          # @option opts [String] :args the arguments of the method to invoke
          # @return [Rex::Java::Serialization::Model::Stream]
          def invoke_stream(opts = {})
            obj_id = opts[:obj_id] || "\x00" * 22
            object_name = opts[:object] || ''
            method_name = opts[:method] || ''
            arguments = opts[:args] || {}
            builder = Rex::Java::Serialization::Builder.new

            block_data = Rex::Java::Serialization::Model::BlockData.new(nil, "#{obj_id}\xff\xff\xff\xff\x13\xe7\xd6\x94\x17\xe5\xda\x20")

            new_object = builder.new_object(
              name: 'javax.management.ObjectName',
              serial: 0xf03a71beb6d15cf, # serialVersionUID
              flags: 3
            )

            data_binary = builder.new_array(
              name: '[B',
              serial: 0xacf317f8060854e0, # serialVersionUID
              values_type: 'byte',
              values: invoke_arguments_stream(arguments).encode.unpack('C*')
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
              values: arguments.keys.collect { |k| Rex::Java::Serialization::Model::Utf.new(nil, k) }
            )

            stream = Rex::Java::Serialization::Model::Stream.new
            stream.contents << block_data
            stream.contents << new_object
            stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, object_name)
            stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
            stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, method_name)
            stream.contents << marshall_object
            stream.contents << new_array
            stream.contents << Rex::Java::Serialization::Model::NullReference.new

            stream
          end

          # Builds a Rex::Java::Serialization::Model::Stream with the arguments to
          # simulate a call to the Java invoke method method.
          #
          # @param args [Hash] the arguments of the method to invoke
          # @return [Rex::Java::Serialization::Model::Stream]
          def invoke_arguments_stream(args = {})
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
