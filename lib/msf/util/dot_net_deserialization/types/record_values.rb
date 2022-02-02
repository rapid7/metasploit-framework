module Msf
module Util
module DotNetDeserialization
module Types
module RecordValues

  #
  # .NET Serialization Types (Records)
  #
  class ArraySingleString < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/3d98fd60-d2b4-448a-ac0b-3cd8dea41f9d
    RECORD_TYPE =          Enums::RecordTypeEnum[:ArraySingleString]
    endian                 :little
    array_info             :array_info
    array                  :members, type: :record, initial_length: -> { array_info.member_count }
  end

  class BinaryLibrary < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/7fcf30e1-4ad4-4410-8f1a-901a4a1ea832
    RECORD_TYPE =          Enums::RecordTypeEnum[:BinaryLibrary]
    endian                 :little
    obj_id                 :library_id
    length_prefixed_string :library_name
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
