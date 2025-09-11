# -*- coding: binary -*-

require 'bindata'

module Rex::Proto::MsTds
  class MsTdsLogin7Password < RubySMB::Field::String16
    default_parameter encode: true

    def read_and_return_value(io)
      value = super
      if value.bytes.each_with_index.all? { _1 == 0xa5 || (_2 % 2) == 0 }
        value = self.class.decode(value)
      end
      value
    end

    def value_to_binary_string(val)
      val = self.class.encode(val) if get_parameter(:encode)
      super(val)
    end

    def self.decode(value)
      value.unpack("C*").map { |c| ((((c ^ 0xa5) & 0x0f) << 4) + (((c ^ 0xa5) & 0xf0) >> 4)) }.pack("C*").force_encoding(Encoding::UTF_16LE)
    end

    def self.encode(value)
      value = value.encode(Encoding::UTF_16LE)
      value.unpack('C*').map { |c| (((c & 0x0f) << 4) + ((c & 0xf0) >> 4)) ^ 0xa5 }.pack('C*')
    end
  end
end