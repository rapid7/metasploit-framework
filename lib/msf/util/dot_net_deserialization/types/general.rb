module Msf
module Util
module DotNetDeserialization
module Types
module General

  #
  # .NET Serialization Types (General)
  #
  class ArrayInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/8fac763f-e46d-43a1-b360-80eb83d2c5fb
    endian                 :little
    obj_id                 :obj_id
    int32                  :member_count
  end

  class ClassInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/0a192be0-58a1-41d0-8a54-9c91db0ab7bf
    endian                 :little
    obj_id                 :obj_id
    length_prefixed_string :name
    int32                  :member_count, value: -> { member_names.length }
    array                  :member_names, type: :length_prefixed_string, read_until: -> { index == member_count - 1 }
  end

  class ClassTypeInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/844b24dd-9f82-426e-9b98-05334307a239
    endian                 :little
    length_prefixed_string :type_name
    int32                  :library_id
  end

  class MemberTypeInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/aa509b5a-620a-4592-a5d8-7e9613e0a03e
    endian                   :little
    default_parameter        member_count: 0
    enum_array               :binary_type_enums, enum: Enums::BinaryTypeEnum, initial_length: :member_count
    array                    :additional_infos, initial_length: -> { filter_binary_type_enums.length } do
      choice                 :additional_info, selection: -> { selection_routine(index) } do
        uint8                  Enums::BinaryTypeEnum[:Primitive]
        length_prefixed_string Enums::BinaryTypeEnum[:SystemClass]
        class_type_info        Enums::BinaryTypeEnum[:Class]
        uint8                  Enums::BinaryTypeEnum[:PrimitiveArray]
      end
    end

    def member_types
      infos = []
      additional_info_index = 0
      binary_type_enums.each do |binary_type|
        additional_info = nil
        if has_additional_info?(binary_type)
          additional_info = additional_infos[additional_info_index].snapshot
          additional_info_index += 1
        end
        infos << {binary_type: binary_type, additional_info: additional_info}
      end
      infos
    end

    private

    def has_additional_info?(binary_type)
      [
        Enums::BinaryTypeEnum[:Primitive],
        Enums::BinaryTypeEnum[:SystemClass],
        Enums::BinaryTypeEnum[:Class],
        Enums::BinaryTypeEnum[:PrimitiveArray]
      ].include? binary_type
    end

    def filter_binary_type_enums
      binary_type_enums.select { |binary_type|
        has_additional_info?(binary_type)
      }
    end

    def selection_routine(index)
      filter_binary_type_enums[index]
    end
  end

  class MessageFlags < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/67213df2-7c15-4543-8e08-42ae0f7c66bf
    endian :little

    bit1   :method_signature_in_array
    bit1   :context_in_array
    bit1   :context_inline
    bit1   :no_context
    bit1   :args_in_array
    bit1   :args_is_array
    bit1   :args_inline
    bit1   :no_args

    bit1   :generic_method
    bit1   :unused1
    bit1   :exception_in_array
    bit1   :return_value_in_array
    bit1   :return_value_inline
    bit1   :return_value_void
    bit1   :no_return_value
    bit1   :properties_in_array

    uint16 :unused2
  end

end
end
end
end
end
