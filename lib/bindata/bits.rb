require 'bindata/single'

module BinData
  # Provides a number of classes that contain an integer.  The integer
  # is defined by endian, signedness and number of bytes.

  module BitField #:nodoc: all
    def self.create_methods(klass, nbits, endian)
      min = 0
      max = (1 << nbits) - 1
      clamp = "val = (val < #{min}) ? #{min} : (val > #{max}) ? #{max} : val"

      # allow single bits to be used as booleans
      if nbits == 1
        clamp = "val = (val == true) ? 1 : (not val) ? 0 : #{clamp}"
      end

      define_methods(klass, nbits, endian.inspect, clamp)
    end

    def self.define_methods(klass, nbits, endian, clamp)
      # define methods in the given class
      klass.module_eval <<-END
        def value=(val)
          #{clamp}
          super(val)
        end

        #---------------
        private

        def _do_write(io)
          raise "can't write whilst reading" if @in_read
          io.writebits(_value, #{nbits}, #{endian})
        end

        def _do_num_bytes(ignored)
          #{nbits} / 8.0
        end

        def read_val(io)
          io.readbits(#{nbits}, #{endian})
        end

        def sensible_default
          0
        end
      END
    end
  end

  # 1 bit big endian bitfield.
  class Bit1 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 1, :big)
  end

  # 1 bit little endian bitfield.
  class Bit1le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 1, :little)
  end

  # 2 bit big endian bitfield.
  class Bit2 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 2, :big)
  end

  # 2 bit little endian bitfield.
  class Bit2le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 2, :little)
  end

  # 3 bit big endian bitfield.
  class Bit3 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 3, :big)
  end

  # 3 bit little endian bitfield.
  class Bit3le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 3, :little)
  end

  # 4 bit big endian bitfield.
  class Bit4 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 4, :big)
  end

  # 4 bit little endian bitfield.
  class Bit4le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 4, :little)
  end

  # 5 bit big endian bitfield.
  class Bit5 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 5, :big)
  end

  # 5 bit little endian bitfield.
  class Bit5le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 5, :little)
  end

  # 6 bit big endian bitfield.
  class Bit6 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 6, :big)
  end

  # 6 bit little endian bitfield.
  class Bit6le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 6, :little)
  end

  # 7 bit big endian bitfield.
  class Bit7 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 7, :big)
  end

  # 7 bit little endian bitfield.
  class Bit7le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 7, :little)
  end

  # 8 bit big endian bitfield.
  class Bit8 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 8, :big)
  end

  # 8 bit little endian bitfield.
  class Bit8le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 8, :little)
  end

  # 9 bit big endian bitfield.
  class Bit9 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 9, :big)
  end

  # 9 bit little endian bitfield.
  class Bit9le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 9, :little)
  end

  # 10 bit big endian bitfield.
  class Bit10 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 10, :big)
  end

  # 10 bit little endian bitfield.
  class Bit10le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 10, :little)
  end

  # 11 bit big endian bitfield.
  class Bit11 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 11, :big)
  end

  # 11 bit little endian bitfield.
  class Bit11le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 11, :little)
  end

  # 12 bit big endian bitfield.
  class Bit12 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 12, :big)
  end

  # 12 bit little endian bitfield.
  class Bit12le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 12, :little)
  end

  # 13 bit big endian bitfield.
  class Bit13 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 13, :big)
  end

  # 13 bit little endian bitfield.
  class Bit13le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 13, :little)
  end

  # 14 bit big endian bitfield.
  class Bit14 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 14, :big)
  end

  # 14 bit little endian bitfield.
  class Bit14le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 14, :little)
  end

  # 15 bit big endian bitfield.
  class Bit15 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 15, :big)
  end

  # 15 bit little endian bitfield.
  class Bit15le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 15, :little)
  end

  # 16 bit big endian bitfield.
  class Bit16 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 16, :big)
  end

  # 16 bit little endian bitfield.
  class Bit16le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 16, :little)
  end

  # 17 bit big endian bitfield.
  class Bit17 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 17, :big)
  end

  # 17 bit little endian bitfield.
  class Bit17le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 17, :little)
  end

  # 18 bit big endian bitfield.
  class Bit18 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 18, :big)
  end

  # 18 bit little endian bitfield.
  class Bit18le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 18, :little)
  end

  # 19 bit big endian bitfield.
  class Bit19 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 19, :big)
  end

  # 19 bit little endian bitfield.
  class Bit19le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 19, :little)
  end

  # 20 bit big endian bitfield.
  class Bit20 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 20, :big)
  end

  # 20 bit little endian bitfield.
  class Bit20le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 20, :little)
  end

  # 21 bit big endian bitfield.
  class Bit21 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 21, :big)
  end

  # 21 bit little endian bitfield.
  class Bit21le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 21, :little)
  end

  # 22 bit big endian bitfield.
  class Bit22 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 22, :big)
  end

  # 22 bit little endian bitfield.
  class Bit22le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 22, :little)
  end

  # 23 bit big endian bitfield.
  class Bit23 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 23, :big)
  end

  # 23 bit little endian bitfield.
  class Bit23le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 23, :little)
  end

  # 24 bit big endian bitfield.
  class Bit24 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 24, :big)
  end

  # 24 bit little endian bitfield.
  class Bit24le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 24, :little)
  end

  # 25 bit big endian bitfield.
  class Bit25 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 25, :big)
  end

  # 25 bit little endian bitfield.
  class Bit25le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 25, :little)
  end

  # 26 bit big endian bitfield.
  class Bit26 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 26, :big)
  end

  # 26 bit little endian bitfield.
  class Bit26le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 26, :little)
  end

  # 27 bit big endian bitfield.
  class Bit27 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 27, :big)
  end

  # 27 bit little endian bitfield.
  class Bit27le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 27, :little)
  end

  # 28 bit big endian bitfield.
  class Bit28 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 28, :big)
  end

  # 28 bit little endian bitfield.
  class Bit28le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 28, :little)
  end

  # 29 bit big endian bitfield.
  class Bit29 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 29, :big)
  end

  # 29 bit little endian bitfield.
  class Bit29le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 29, :little)
  end

  # 30 bit big endian bitfield.
  class Bit30 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 30, :big)
  end

  # 30 bit little endian bitfield.
  class Bit30le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 30, :little)
  end

  # 31 bit big endian bitfield.
  class Bit31 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 31, :big)
  end

  # 31 bit little endian bitfield.
  class Bit31le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 31, :little)
  end

  # 32 bit big endian bitfield.
  class Bit32 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 32, :big)
  end

  # 32 bit little endian bitfield.
  class Bit32le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 32, :little)
  end

  # 33 bit big endian bitfield.
  class Bit33 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 33, :big)
  end

  # 33 bit little endian bitfield.
  class Bit33le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 33, :little)
  end

  # 34 bit big endian bitfield.
  class Bit34 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 34, :big)
  end

  # 34 bit little endian bitfield.
  class Bit34le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 34, :little)
  end

  # 35 bit big endian bitfield.
  class Bit35 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 35, :big)
  end

  # 35 bit little endian bitfield.
  class Bit35le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 35, :little)
  end

  # 36 bit big endian bitfield.
  class Bit36 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 36, :big)
  end

  # 36 bit little endian bitfield.
  class Bit36le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 36, :little)
  end

  # 37 bit big endian bitfield.
  class Bit37 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 37, :big)
  end

  # 37 bit little endian bitfield.
  class Bit37le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 37, :little)
  end

  # 38 bit big endian bitfield.
  class Bit38 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 38, :big)
  end

  # 38 bit little endian bitfield.
  class Bit38le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 38, :little)
  end

  # 39 bit big endian bitfield.
  class Bit39 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 39, :big)
  end

  # 39 bit little endian bitfield.
  class Bit39le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 39, :little)
  end

  # 40 bit big endian bitfield.
  class Bit40 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 40, :big)
  end

  # 40 bit little endian bitfield.
  class Bit40le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 40, :little)
  end

  # 41 bit big endian bitfield.
  class Bit41 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 41, :big)
  end

  # 41 bit little endian bitfield.
  class Bit41le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 41, :little)
  end

  # 42 bit big endian bitfield.
  class Bit42 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 42, :big)
  end

  # 42 bit little endian bitfield.
  class Bit42le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 42, :little)
  end

  # 43 bit big endian bitfield.
  class Bit43 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 43, :big)
  end

  # 43 bit little endian bitfield.
  class Bit43le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 43, :little)
  end

  # 44 bit big endian bitfield.
  class Bit44 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 44, :big)
  end

  # 44 bit little endian bitfield.
  class Bit44le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 44, :little)
  end

  # 45 bit big endian bitfield.
  class Bit45 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 45, :big)
  end

  # 45 bit little endian bitfield.
  class Bit45le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 45, :little)
  end

  # 46 bit big endian bitfield.
  class Bit46 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 46, :big)
  end

  # 46 bit little endian bitfield.
  class Bit46le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 46, :little)
  end

  # 47 bit big endian bitfield.
  class Bit47 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 47, :big)
  end

  # 47 bit little endian bitfield.
  class Bit47le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 47, :little)
  end

  # 48 bit big endian bitfield.
  class Bit48 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 48, :big)
  end

  # 48 bit little endian bitfield.
  class Bit48le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 48, :little)
  end

  # 49 bit big endian bitfield.
  class Bit49 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 49, :big)
  end

  # 49 bit little endian bitfield.
  class Bit49le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 49, :little)
  end

  # 50 bit big endian bitfield.
  class Bit50 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 50, :big)
  end

  # 50 bit little endian bitfield.
  class Bit50le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 50, :little)
  end

  # 51 bit big endian bitfield.
  class Bit51 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 51, :big)
  end

  # 51 bit little endian bitfield.
  class Bit51le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 51, :little)
  end

  # 52 bit big endian bitfield.
  class Bit52 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 52, :big)
  end

  # 52 bit little endian bitfield.
  class Bit52le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 52, :little)
  end

  # 53 bit big endian bitfield.
  class Bit53 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 53, :big)
  end

  # 53 bit little endian bitfield.
  class Bit53le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 53, :little)
  end

  # 54 bit big endian bitfield.
  class Bit54 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 54, :big)
  end

  # 54 bit little endian bitfield.
  class Bit54le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 54, :little)
  end

  # 55 bit big endian bitfield.
  class Bit55 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 55, :big)
  end

  # 55 bit little endian bitfield.
  class Bit55le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 55, :little)
  end

  # 56 bit big endian bitfield.
  class Bit56 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 56, :big)
  end

  # 56 bit little endian bitfield.
  class Bit56le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 56, :little)
  end

  # 57 bit big endian bitfield.
  class Bit57 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 57, :big)
  end

  # 57 bit little endian bitfield.
  class Bit57le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 57, :little)
  end

  # 58 bit big endian bitfield.
  class Bit58 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 58, :big)
  end

  # 58 bit little endian bitfield.
  class Bit58le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 58, :little)
  end

  # 59 bit big endian bitfield.
  class Bit59 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 59, :big)
  end

  # 59 bit little endian bitfield.
  class Bit59le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 59, :little)
  end

  # 60 bit big endian bitfield.
  class Bit60 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 60, :big)
  end

  # 60 bit little endian bitfield.
  class Bit60le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 60, :little)
  end

  # 61 bit big endian bitfield.
  class Bit61 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 61, :big)
  end

  # 61 bit little endian bitfield.
  class Bit61le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 61, :little)
  end

  # 62 bit big endian bitfield.
  class Bit62 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 62, :big)
  end

  # 62 bit little endian bitfield.
  class Bit62le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 62, :little)
  end

  # 63 bit big endian bitfield.
  class Bit63 < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 63, :big)
  end

  # 63 bit little endian bitfield.
  class Bit63le < BinData::Single
    register(self.name, self)
    BitField.create_methods(self, 63, :little)
  end
end