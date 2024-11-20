module Msf
module Util
module DotNetDeserialization
module Types
module CommonStructures

  #
  # .NET Serialization Types (Common Structures)
  # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/acd7fe17-615c-467f-b700-e5e8761b8637
  #
  class ValueWithCode < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/0418b4a2-1e52-45dc-8622-1b619fa3ffec
    endian                 :little

    uint8                  :primitive_type_enum
    choice                 :val, selection: :primitive_type_enum do
      boolean                Enums::PrimitiveTypeEnum[:Boolean]
      uint8                  Enums::PrimitiveTypeEnum[:Byte]
      double                 Enums::PrimitiveTypeEnum[:Double]
      int16                  Enums::PrimitiveTypeEnum[:Int16]
      int32                  Enums::PrimitiveTypeEnum[:Int32]
      int64                  Enums::PrimitiveTypeEnum[:Int64]
      int8                   Enums::PrimitiveTypeEnum[:SByte]
      float                  Enums::PrimitiveTypeEnum[:Single]
      int64                  Enums::PrimitiveTypeEnum[:TimeSpan]
      date_time              Enums::PrimitiveTypeEnum[:DateTime]
      uint16                 Enums::PrimitiveTypeEnum[:UInt16]
      uint32                 Enums::PrimitiveTypeEnum[:UInt32]
      uint64                 Enums::PrimitiveTypeEnum[:UInt64]
      null                   Enums::PrimitiveTypeEnum[:Null]
      length_prefixed_string Enums::PrimitiveTypeEnum[:String]
    end
  end

  class StringValueWithCode < BinData::Primitive
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/ecc20dd0-1d83-4a22-b4b2-23c58b03dffc
    endian                 :little

    uint8                  :primitive_type_enum, value: Enums::PrimitiveTypeEnum[:String]
    length_prefixed_string :string_value

    def get
      self.string_value
    end

    def set(v)
      self.string_value = value
    end
  end

  class ArrayOfValueWithCode < BinData::Primitive
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/330f623e-7412-46c9-8ae0-59543bbfee86
    endian                  :little

    int32                   :list_length, initial_value: -> { list_of_value_with_code.length }
    array                   :list_of_value_with_code, type: :value_with_code, initial_length: :list_length

    def get
      self.list_of_value_with_code
    end

    def set(v)
      self.list_of_value_with_code = v
    end
  end
end
end
end
end
end
