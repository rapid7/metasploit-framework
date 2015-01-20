# -*- coding: binary -*-

module Msf
  module Jmx
    module MBean
      module ServerConnection

        def create_mbean_stream(id, name)
          stream = Rex::Java::Serialization::Model::Stream.new

          block_data = Rex::Java::Serialization::Model::BlockData.new
          block_data.contents << id
          block_data.contents << "\xff\xff\xff\xff\x22\xd7\xfd\x4a\x90\x6a\xc8\xe6"
          block_data.length = block_data.contents.length

          stream.contents << block_data
          stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, name)
          stream.contents << Rex::Java::Serialization::Model::NullReference.new
          stream.contents << Rex::Java::Serialization::Model::NullReference.new

          stream
        end

        def get_object_instance_stream(id, name)
          builder = Rex::Java::Serialization::Builder.new
          stream = Rex::Java::Serialization::Model::Stream.new

          block_data = Rex::Java::Serialization::Model::BlockData.new
          block_data.contents = id
          block_data.contents << "\xff\xff\xff\xff\x60\x73\xb3\x36\x1f\x37\xbd\xc2"
          block_data.length = block_data.contents.length

          stream.contents << block_data

          new_object = builder.new_object(
            name: 'javax.management.ObjectName',
            serial: 0xf03a71beb6d15cf,
            flags: 3
          )
          stream.contents << new_object
          stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, name)
          stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
          stream.contents << Rex::Java::Serialization::Model::NullReference.new

          stream
        end

        def invoke_stream(id, object_name, method_name, arguments)
          builder = Rex::Java::Serialization::Builder.new
          stream = Rex::Java::Serialization::Model::Stream.new

          block_data = Rex::Java::Serialization::Model::BlockData.new
          block_data.contents = id
          block_data.contents  << "\xff\xff\xff\xff\x13\xe7\xd6\x94\x17\xe5\xda\x20"
          block_data.length = block_data.contents.length

          stream.contents << block_data

          new_object = builder.new_object(
            name: 'javax.management.ObjectName',
            serial: 0xf03a71beb6d15cf,
            flags: 3
          )

          stream.contents << new_object
          stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, object_name)
          stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
          stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, method_name)

          data_binary = builder.new_array(
            name: '[B',
            serial: 0xacf317f8060854e0,
            values_type: 'byte',
            values: invoke_arguments_stream(arguments).encode.unpack('C*')
          )

          marshall_object = builder.new_object(
            name: 'java.rmi.MarshalledObject',
            serial: 0x7cbd1e97ed63fc3e,
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
          stream.contents << marshall_object

          new_array = builder.new_array(
            name: '[Ljava.lang.String;',
            serial: 0xadd256e7e91d7b47,
            values_type: 'java.lang.String;',
            values: arguments.keys.collect { |k| Rex::Java::Serialization::Model::Utf.new(nil, k) }
          )

          stream.contents << new_array

          stream.contents << Rex::Java::Serialization::Model::NullReference.new

          stream
        end

        def invoke_arguments_stream(arguments)
          builder = Rex::Java::Serialization::Builder.new
          stream = Rex::Java::Serialization::Model::Stream.new

          new_array = builder.new_array(
            name: '[Ljava.lang.Object;',
            serial: 0x90ce589f1073296c,
            annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
            values_type: 'java.lang.Object;',
            values: arguments.values.collect { |arg| Rex::Java::Serialization::Model::Utf.new(nil, arg) }
          )
          stream.contents << new_array

          stream
        end
      end
    end
  end
end
