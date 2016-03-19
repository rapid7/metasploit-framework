# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      # This class provides a builder to help in the construction of
      # Java serialized contents.
      class Builder

        # Creates a Rex::Java::Serialization::Model::NewArray
        #
        # @param opts [Hash{Symbol => <Rex::Java::Serialization::Model::NewClassDesc, String, Array>}]
        # @option opts [Rex::Java::Serialization::Model::NewClassDesc] :description
        # @option opts [String] :values_type
        # @option opts [Array] :values
        # @return [Rex::Java::Serialization::Model::NewArray]
        # @see #new_class
        def new_array(opts = {})
          class_desc = opts[:description] || new_class(opts)
          type = opts[:values_type] || ''
          values = opts[:values] || []

          array = Rex::Java::Serialization::Model::NewArray.new
          array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
          array.array_description.description = class_desc
          array.type = type
          array.values = values

          array
        end

        # Creates a Rex::Java::Serialization::Model::NewObject
        #
        # @param opts [Hash{Symbol => <Rex::Java::Serialization::Model::NewClassDesc, Array>}]
        # @option opts [Rex::Java::Serialization::Model::NewClassDesc] :description
        # @option opts [Array] :data
        # @return [Rex::Java::Serialization::Model::NewObject]
        # @see #new_class
        def new_object(opts = {})
          class_desc = opts[:description] || new_class(opts)
          data = opts[:data] || []

          object = Rex::Java::Serialization::Model::NewObject.new
          object.class_desc = Rex::Java::Serialization::Model::ClassDesc.new
          object.class_desc.description = class_desc
          object.class_data = data

          object
        end

        # Creates a Rex::Java::Serialization::Model::NewClassDesc
        #
        # @param opts [Hash{Symbol => <Rex::Java::Serialization::Model::NewClassDesc, Array>}]
        # @option opts [String] :name
        # @option opts [Fixnum] :serial
        # @option opts [Fixnum] :flags
        # @option opts [Array] :fields
        # @option opts [Array] :annotations
        # @option opts [Rex::Java::Serialization::Model::Element] :super_class
        # @return [Rex::Java::Serialization::Model::NewClassDesc]
        def new_class(opts = {})
          class_name = opts[:name] || ''
          serial_version = opts[:serial] || 0
          flags = opts[:flags] || 2
          fields = opts[:fields] || []
          annotations = opts[:annotations] || [Rex::Java::Serialization::Model::NullReference.new,
                                               Rex::Java::Serialization::Model::EndBlockData.new]
          super_class = opts[:super_class] || Rex::Java::Serialization::Model::NullReference.new

          class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
          class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, class_name)
          class_desc.serial_version = serial_version
          class_desc.flags = flags
          class_desc.fields = []

          fields.each do |f|
            field = Rex::Java::Serialization::Model::Field.new
            field.type = f[0]
            field.name = Rex::Java::Serialization::Model::Utf.new(nil, f[1])
            field.field_type = Rex::Java::Serialization::Model::Utf.new(nil, f[2]) if f[2]
            class_desc.fields << field
          end

          class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
          class_desc.class_annotation.contents = annotations
          class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
          class_desc.super_class.description = super_class

          class_desc
        end
      end
    end
  end
end