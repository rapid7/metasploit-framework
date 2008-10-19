require 'bindata/single'

module BinData
  # Provides a number of classes that contain a floating point number.
  # The float is defined by endian, and precision.

  module Float #:nodoc: all
    def self.create_float_methods(klass, single_precision, endian)
      read = create_read_code(single_precision, endian)
      to_s = create_to_s_code(single_precision, endian)

      define_methods(klass, single_precision, read, to_s)
    end

    def self.create_read_code(single_precision, endian)
      if single_precision
        unpack = (endian == :little) ? 'e' : 'g'
        nbytes = 4
      else # double_precision
        unpack = (endian == :little) ? 'E' : 'G'
        nbytes = 8
      end

      "io.readbytes(#{nbytes}).unpack('#{unpack}').at(0)"
    end

    def self.create_to_s_code(single_precision, endian)
      if single_precision
        pack = (endian == :little) ? 'e' : 'g'
      else # double_precision
        pack = (endian == :little) ? 'E' : 'G'
      end

      "[val].pack('#{pack}')"
    end

    def self.define_methods(klass, single_precision, read, to_s)
      nbytes = single_precision ? 4 : 8

      # define methods in the given class
      klass.module_eval <<-END
        def _do_num_bytes(ignored)
          #{nbytes}
        end

        #---------------
        private

        def sensible_default
          0.0
        end

        def val_to_str(val)
          #{to_s}
        end

        def read_val(io)
          #{read}
        end
      END
    end
  end


  # Single precision floating point number in little endian format
  class FloatLe < BinData::Single
    register(self.name, self)
    Float.create_float_methods(self, true, :little)
  end

  # Single precision floating point number in big endian format
  class FloatBe < BinData::Single
    register(self.name, self)
    Float.create_float_methods(self, true, :big)
  end

  # Double precision floating point number in little endian format
  class DoubleLe < BinData::Single
    register(self.name, self)
    Float.create_float_methods(self, false, :little)
  end

  # Double precision floating point number in big endian format
  class DoubleBe < BinData::Single
    register(self.name, self)
    Float.create_float_methods(self, false, :big)
  end
end