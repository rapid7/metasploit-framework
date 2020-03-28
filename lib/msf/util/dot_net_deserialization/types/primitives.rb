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

    def set(v)
      self.val = v ? 1 : 0
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
      raise ArgumentError.new('kind_name must be either :unspecified, :utc, or :local') if value.nil?
      value
    end
  end

  class LengthPrefixedString < BinData::BasePrimitive
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/10b218f5-9b2b-4947-b4b7-07725a2c8127
    def assign(val)
      super(binary_string(val))
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
          raise Msf::Exception('The value exceeds the 5 byte limit for 7-bit encoded integers')
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

    def set(v)
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

    def set(v)
      self.val = v
      register_self
    end

    protected

    def register_self
      stream = DotNetDeserialization.get_ancestor(self, SerializedStream, required: false)
      return if stream.nil?
      stream.set_object(self.val.value, DotNetDeserialization.get_ancestor(self, Record))
    end
  end

end
end
end
end
end
