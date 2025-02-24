module Msf
module Util
module DotNetDeserialization
module Types
module RecordValues

  #
  # .NET Serialization Types (Records)
  #
  class ArraySinglePrimitive < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/3a50a305-5f32-48a1-a42a-c34054db310b
    RECORD_TYPE =         Enums::RecordTypeEnum[:ArraySinglePrimitive]
    endian                :little
    array_info            :array_info
    uint8                 :primitive_type_enum
    choice                :members, selection: :primitive_type_enum do
      array               Enums::PrimitiveTypeEnum[:Boolean],  type: :boolean,   initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:Byte],     type: :uint8,     initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:Double],   type: :double,    initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:Int16],    type: :int16,     initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:Int32],    type: :int32,     initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:Int64],    type: :int64,     initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:SByte],    type: :int8,      initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:Single],   type: :float,     initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:TimeSpan], type: :int64,     initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:DateTime], type: :date_time, initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:UInt16],   type: :uint16,    initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:UInt32],   type: :uint32,    initial_length: -> { array_info.member_count }
      array               Enums::PrimitiveTypeEnum[:UInt64],   type: :uint64,    initial_length: -> { array_info.member_count }
    end
  end

  class ArraySingleObject < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/982b2f50-6367-402a-aaf2-44ee96e2a5e0
    RECORD_TYPE =          Enums::RecordTypeEnum[:ArraySingleObject]
    endian                 :little
    array_info             :array_info
  end

  class ArraySingleString < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/3d98fd60-d2b4-448a-ac0b-3cd8dea41f9d
    RECORD_TYPE =          Enums::RecordTypeEnum[:ArraySingleString]
    endian                 :little
    array_info             :array_info
    array                  :members, type: :record, initial_length: -> { array_info.member_count }
  end

  class BinaryArray < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/9c62c928-db4e-43ca-aeba-146256ef67c2
    RECORD_TYPE =          Enums::RecordTypeEnum[:BinaryArray]
    endian                 :little
    obj_id                 :obj_id
    uint8                  :binary_array_type_enum
    int32                  :rank
    array                  :lengths, type: :int32, initial_length: :rank
    array                  :lower_bounds, type: :int32, initial_length: :rank, onlyif: :has_lower_bounds?
    uint8                  :type_enum
    choice                 :additional_type_info, selection: :type_enum, onlyif: :has_additional_type_info? do
      uint8                   Enums::BinaryTypeEnum[:Primitive]
      length_prefixed_string  Enums::BinaryTypeEnum[:SystemClass]
      class_type_info         Enums::BinaryTypeEnum[:Class]
      uint8                   Enums::BinaryTypeEnum[:PrimitiveArray]
    end

    private

    def has_additional_type_info?
      [
        Enums::BinaryTypeEnum[:Primitive],
        Enums::BinaryTypeEnum[:SystemClass],
        Enums::BinaryTypeEnum[:Class],
        Enums::BinaryTypeEnum[:PrimitiveArray],
      ].include? type_enum
    end

    def has_lower_bounds?
      [
        Enums::BinaryArrayTypeEnum[:SingleOffset],
        Enums::BinaryArrayTypeEnum[:JaggedOffset],
        Enums::BinaryArrayTypeEnum[:RectangleOffset]
      ].include? binary_array_type_enum
    end
  end

  class BinaryLibrary < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/7fcf30e1-4ad4-4410-8f1a-901a4a1ea832
    RECORD_TYPE =          Enums::RecordTypeEnum[:BinaryLibrary]
    endian                 :little
    obj_id                 :library_id
    length_prefixed_string :library_name
  end

  class BinaryMethodCall < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/ddb4da3d-8cd7-414f-b984-1a509d985bd2
    RECORD_TYPE =            Enums::RecordTypeEnum[:MethodCall]
    endian                   :little
    message_flags            :message_enum
    string_value_with_code   :method_name
    string_value_with_code   :type_name
    string_value_with_code   :call_context, onlyif: -> { message_enum.context_inline != 0 }
    array_of_value_with_code :args, onlyif: -> { message_enum.args_inline != 0 }
  end

  class BinaryMethodReturn < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/1b34e743-38ac-47bd-8c8d-2fca1cd417b7
    RECORD_TYPE =            Enums::RecordTypeEnum[:MethodReturn]
    endian                   :little
    message_flags            :message_enum
    value_with_code          :return_value, onlyif: -> { message_enum.return_value_inline != 0 }
    string_value_with_code   :call_context, onlyif: -> { message_enum.context_inline != 0 }
    array_of_value_with_code :args, onlyif: -> { message_enum.args_inline != 0 }
  end

  class BinaryObjectString < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/eb503ca5-e1f6-4271-a7ee-c4ca38d07996
    RECORD_TYPE =          Enums::RecordTypeEnum[:BinaryObjectString]
    endian                 :little
    obj_id                 :obj_id
    length_prefixed_string :string
  end

  class ClassWithId < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/2d168388-37f4-408a-b5e0-e48dbce73e26
    RECORD_TYPE =          Enums::RecordTypeEnum[:ClassWithId]
    endian                 :little
    obj_id                 :obj_id
    int32                  :metadata_id
    member_values          :member_values, class_info: -> { class_info }, member_type_info: -> { member_type_info }

    def class_info
      stream = DotNetDeserialization.get_ancestor(self, SerializedStream)
      object = stream.get_object(metadata_id)
      object.class_info
    end

    def member_type_info
      stream = DotNetDeserialization.get_ancestor(self, SerializedStream)
      object = stream.get_object(metadata_id)
      object.member_type_info
    end

    extend Primitives::MemberValues::Factory
  end

  class ClassWithMembersAndTypes < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/847b0b6a-86af-4203-8ed0-f84345f845b9
    RECORD_TYPE =          Enums::RecordTypeEnum[:ClassWithMembersAndTypes]
    endian                 :little
    class_info             :class_info
    member_type_info       :member_type_info, member_count: -> { class_info.member_count }
    int32                  :library_id
    member_values          :member_values, class_info: -> { class_info }, member_type_info: -> { member_type_info }

    extend Primitives::MemberValues::Factory
  end

  class MemberReference < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/eef0aa32-ab03-4b6a-a506-bcdfc10583fd
    RECORD_TYPE =          Enums::RecordTypeEnum[:MemberReference]
    endian                 :little
    int32                  :id_ref
  end

  class MessageEnd < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/de6a574b-c596-4d83-9df7-63c0077acd32
    RECORD_TYPE =          Enums::RecordTypeEnum[:MessageEnd]
    endian                 :little
  end

  class ObjectNull < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/fe51522c-23d1-48dd-9913-c84894abc127
    RECORD_TYPE =          Enums::RecordTypeEnum[:ObjectNull]
    endian                 :little
  end

  class SerializationHeaderRecord < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/a7e578d3-400a-4249-9424-7529d10d1b3c
    RECORD_TYPE =          Enums::RecordTypeEnum[:SerializedStreamHeader]
    endian                 :little
    default_parameter      major_version: 1
    default_parameter      minor_version: 0
    int32                  :root_id
    int32                  :header_id
    int32                  :major_version, initial_value: :major_version
    int32                  :minor_version, initial_value: :minor_version
  end

  class SystemClassWithMembers < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/f5bd730f-d944-42ab-b6b3-013099559a4b
    RECORD_TYPE =          Enums::RecordTypeEnum[:SystemClassWithMembers]
    endian                 :little
    class_info             :class_info
  end

  class SystemClassWithMembersAndTypes < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/ecb47445-831f-4ef5-9c9b-afd4d06e3657
    RECORD_TYPE =          Enums::RecordTypeEnum[:SystemClassWithMembersAndTypes]
    endian                 :little
    class_info             :class_info
    member_type_info       :member_type_info, member_count: -> { class_info.member_count }
    member_values          :member_values, class_info: -> { class_info }, member_type_info: -> { member_type_info }

    extend Primitives::MemberValues::Factory
  end

end
end
end
end
end
