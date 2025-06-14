module Msf
module Util
module DotNetDeserialization
module Types
module Primitives

  #
  # .NET Serialization Types (Primitives)
  #
  class Boolean < BinData::Primitive
    int8 :val
    def get
      self.val != 0
    end

    def set(value)
      self.val = value ? 1 : 0
    end
  end

  class DateTime < BinData::Primitive
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/f05212bd-57f4-4c4b-9d98-b84c7c658054
    default_parameter kind_name: :unspecified

    endian   :little
    sbit62   :ticks
    bit2     :kind, initial_value: -> { kind_initial_value }

    KindEnum = {
        unspecified: 0,
        utc:         1,
        local:       2
    }

    def get
      self.ticks
    end

    def set(ticks)
      self.ticks = ticks
    end

    def kind_name
      KindEnum.key(kind)
    end

    private

    def kind_initial_value
      value = KindEnum.fetch(get_parameter(:kind_name), nil)
      raise ::ArgumentError, 'Parameter kind_name must be either :unspecified, :utc, or :local' if value.nil?
      value
    end
  end

  class EnumArray < BinData::Array
    mandatory_parameter :enum
    default_parameters  type: :uint8

    def assign(values)
      if values.is_a? ::Array
        enum = eval_parameter(:enum)
        values = values.map { |value| (value.is_a? Symbol) ? enum.fetch(value) : value }
      end

      super(values)
    end
  end

  class LengthPrefixedString < BinData::BasePrimitive
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/10b218f5-9b2b-4947-b4b7-07725a2c8127
    def assign(value)
      super(binary_string(value))
    end

    private

    def value_to_binary_string(string)
      return DotNetDeserialization.encode_7bit_int(string.length) + string
    end

    def read_and_return_value(io)
      # see: https://github.com/microsoft/referencesource/blob/3b1eaf5203992df69de44c783a3eda37d3d4cd10/mscorlib/system/io/binaryreader.cs#L582
      count = 0
      shift = 0
      loop do |i|
        if shift == 5 * 7
          raise ::EncodingError, 'The value exceeds the 5 byte limit for 7-bit encoded integers'
        end
        ch = io.readbytes(1).unpack('C')[0]
        count |= (ch & 0x7f) << shift
        shift += 7
        break if (ch & 0x80) == 0
      end

      io.readbytes(count)
    end

    def sensible_default
      ""
    end
  end

  class Null < BinData::Primitive
    def get
    end

    def set(value)
    end
  end

  class ObjId < BinData::Primitive
    endian                 :little
    int32                  :val
    def do_read(io)
      super(io)
      register_self
    end

    def get
      self.val
    end

    def set(value)
      self.val = value
      register_self
    end

    protected

    def register_self
      stream = DotNetDeserialization.get_ancestor(self, SerializedStream, required: false)
      return if stream.nil?
      stream.set_object(self.val, DotNetDeserialization.get_ancestor(self, Record).record_value)
    end
  end

  class MemberValues < BinData::Array
    endian                   :little
    mandatory_parameter      :class_info
    mandatory_parameter      :member_type_info
    default_parameter        initial_length: -> { class_info.member_count }
    choice                   :member_value, selection: -> { selection_routine(index) } do
      record                  Types::Record
      boolean                 Enums::PrimitiveTypeEnum[:Boolean]
      uint8                   Enums::PrimitiveTypeEnum[:Byte]
      #???                    Enums::PrimitiveTypeEnum[:Char] # todo: implement this primitive type
      length_prefixed_string  Enums::PrimitiveTypeEnum[:Decimal]
      double                  Enums::PrimitiveTypeEnum[:Double]
      int16                   Enums::PrimitiveTypeEnum[:Int16]
      int32                   Enums::PrimitiveTypeEnum[:Int32]
      int64                   Enums::PrimitiveTypeEnum[:Int64]
      int8                    Enums::PrimitiveTypeEnum[:SByte]
      float                   Enums::PrimitiveTypeEnum[:Single]
      int64                   Enums::PrimitiveTypeEnum[:TimeSpan]
      date_time               Enums::PrimitiveTypeEnum[:DateTime]
      uint16                  Enums::PrimitiveTypeEnum[:UInt16]
      uint32                  Enums::PrimitiveTypeEnum[:UInt32]
      uint64                  Enums::PrimitiveTypeEnum[:UInt64]
      null                    Enums::PrimitiveTypeEnum[:Null]
      length_prefixed_string  Enums::PrimitiveTypeEnum[:String]
    end

    private

    def selection_routine(index)
      member_type_info = eval_parameter(:member_type_info)
      if member_type_info.is_a? BinData::Record::Snapshot
        member_type_info = Types::General::MemberTypeInfo.new(member_type_info)
      end

      member_type = member_type_info.member_types[index]
      if member_type[:binary_type] == Enums::BinaryTypeEnum[:Primitive]
        return member_type[:additional_info]
      end

      Types::Record
    end

    module Factory
      def from_member_values(class_info:, member_type_info:, member_values:, **kwargs)
        raise ::ArgumentError, 'Invalid class_info type' unless class_info.is_a? Types::General::ClassInfo
        raise ::ArgumentError, 'Invalid member_type_info type' unless member_type_info.is_a? Types::General::MemberTypeInfo
        raise ::ArgumentError, 'Invalid member count' unless class_info.member_count == member_values.length

        kwargs[:class_info] = class_info
        kwargs[:member_type_info] = member_type_info
        kwargs[:member_values] = MemberValues.new(
          member_values,
          class_info: class_info,
          member_type_info: member_type_info
        )

        # pass class_info and member_type_info as *both* a value and a parameter
        self.new(kwargs, class_info: class_info, member_type_info: member_type_info)
      end
    end
  end

end
end
end
end
end
