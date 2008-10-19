require 'bindata/single'

module BinData
  # Provides a number of classes that contain an integer.  The integer
  # is defined by endian, signedness and number of bytes.

  module Integer #:nodoc: all
    def self.create_int_methods(klass, nbits, endian)
      max = (1 << (nbits - 1)) - 1
      min = -(max + 1)
      clamp = "val = (val < #{min}) ? #{min} : (val > #{max}) ? #{max} : val"

      int2uint = "val = val & #{(1 << nbits) - 1}"
      uint2int = "val = ((val & #{1 << (nbits - 1)}).zero?) ? " +
                 "val & #{max} : -(((~val) & #{max}) + 1)"

      read = create_read_code(nbits, endian)
      to_s = create_to_s_code(nbits, endian)

      define_methods(klass, nbits / 8, clamp, read, to_s, int2uint, uint2int)
    end

    def self.create_uint_methods(klass, nbits, endian)
      min = 0
      max = (1 << nbits) - 1
      clamp = "val = (val < #{min}) ? #{min} : (val > #{max}) ? #{max} : val"

      read = create_read_code(nbits, endian)
      to_s = create_to_s_code(nbits, endian)

      define_methods(klass, nbits / 8, clamp, read, to_s)
    end

    def self.create_read_code(nbits, endian)
      c16 = (endian == :little) ? 'v' : 'n'
      c32 = (endian == :little) ? 'V' : 'N'
      b1  = (endian == :little) ? 0 : 1
      b2  = (endian == :little) ? 1 : 0

      case nbits
      when  8; "io.readbytes(1).unpack('C').at(0)"
      when 16; "io.readbytes(2).unpack('#{c16}').at(0)"
      when 32; "io.readbytes(4).unpack('#{c32}').at(0)"
      when 64; "(a = io.readbytes(8).unpack('#{c32 * 2}'); " +
                     "(a.at(#{b2}) << 32) + a.at(#{b1}))"
      else
        raise "unknown nbits '#{nbits}'"
      end
    end

    def self.create_to_s_code(nbits, endian)
      c16 = (endian == :little) ? 'v' : 'n'
      c32 = (endian == :little) ? 'V' : 'N'
      v1  = (endian == :little) ? 'val' : '(val >> 32)'
      v2  = (endian == :little) ? '(val >> 32)' : 'val'

      case nbits
      when  8; "val.chr"
      when 16; "[val].pack('#{c16}')"
      when 32; "[val].pack('#{c32}')"
      when 64; "[#{v1} & 0xffffffff, #{v2} & 0xffffffff].pack('#{c32 * 2}')"
      else
        raise "unknown nbits '#{nbits}'"
      end
    end

    def self.define_methods(klass, nbytes, clamp, read, to_s,
                            int2uint = nil, uint2int = nil)
      # define methods in the given class
      klass.module_eval <<-END
        def value=(val)
          #{clamp}
          super(val)
        end

        def _do_num_bytes(ignored)
          #{nbytes}
        end

        #---------------
        private

        def sensible_default
          0
        end

        def val_to_str(val)
          #{clamp}
          #{int2uint unless int2uint.nil?}
          #{to_s}
        end

        def read_val(io)
          val = #{read}
          #{uint2int unless uint2int.nil?}
        end
      END
    end
  end


  # Unsigned 1 byte integer.
  class Uint8 < BinData::Single
    register(self.name, self)
    Integer.create_uint_methods(self, 8, :little)
  end

  # Unsigned 2 byte little endian integer.
  class Uint16le < BinData::Single
    register(self.name, self)
    Integer.create_uint_methods(self, 16, :little)
  end

  # Unsigned 2 byte big endian integer.
  class Uint16be < BinData::Single
    register(self.name, self)
    Integer.create_uint_methods(self, 16, :big)
  end

  # Unsigned 4 byte little endian integer.
  class Uint32le < BinData::Single
    register(self.name, self)
    Integer.create_uint_methods(self, 32, :little)
  end

  # Unsigned 4 byte big endian integer.
  class Uint32be < BinData::Single
    register(self.name, self)
    Integer.create_uint_methods(self, 32, :big)
  end

  # Unsigned 8 byte little endian integer.
  class Uint64le < BinData::Single
    register(self.name, self)
    Integer.create_uint_methods(self, 64, :little)
  end

  # Unsigned 8 byte big endian integer.
  class Uint64be < BinData::Single
    register(self.name, self)
    Integer.create_uint_methods(self, 64, :big)
  end

  # Signed 1 byte integer.
  class Int8 < BinData::Single
    register(self.name, self)
    Integer.create_int_methods(self, 8, :little)
  end

  # Signed 2 byte little endian integer.
  class Int16le < BinData::Single
    register(self.name, self)
    Integer.create_int_methods(self, 16, :little)
  end

  # Signed 2 byte big endian integer.
  class Int16be < BinData::Single
    register(self.name, self)
    Integer.create_int_methods(self, 16, :big)
  end

  # Signed 4 byte little endian integer.
  class Int32le < BinData::Single
    register(self.name, self)
    Integer.create_int_methods(self, 32, :little)
  end

  # Signed 4 byte big endian integer.
  class Int32be < BinData::Single
    register(self.name, self)
    Integer.create_int_methods(self, 32, :big)
  end

  # Signed 8 byte little endian integer.
  class Int64le < BinData::Single
    register(self.name, self)
    Integer.create_int_methods(self, 64, :little)
  end

  # Signed 8 byte big endian integer.
  class Int64be < BinData::Single
    register(self.name, self)
    Integer.create_int_methods(self, 64, :big)
  end
end