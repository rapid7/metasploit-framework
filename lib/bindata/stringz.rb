require "bindata/single"

module BinData
  # A BinData::Stringz object is a container for a zero ("\0") terminated
  # string.
  #
  # For convenience, the zero terminator is not necessary when setting the
  # value.  Likewise, the returned value will not be zero terminated.
  #
  #   require 'bindata'
  #
  #   data = "abcd\x00efgh"
  #
  #   obj = BinData::Stringz.new
  #   obj.read(data)
  #   obj.snapshot #=> "abcd"
  #   obj.value #=> "abcd"
  #   obj.num_bytes #=> 5
  #   obj.to_s #=> "abcd\000"
  #
  # == Parameters
  #
  # Stringz objects accept all the params that BinData::Single
  # does, as well as the following:
  #
  # <tt>:max_length</tt>:: The maximum length of the string including the zero
  #                        byte.
  class Stringz < BinData::Single

    # Register this class
    register(self.name, self)

    # These are the parameters used by this class.
    optional_parameters :max_length

    # Overrides value to return the value of this data excluding the trailing
    # zero byte.
    def value
      v = super
      val_to_str(v).chomp("\0")
    end

    #---------------
    private

    # Returns +val+ ensuring it is zero terminated and no longer
    # than <tt>:max_length</tt> bytes.
    def val_to_str(val)
      zero_terminate(val, eval_param(:max_length))
    end

    # Read a number of bytes from +io+ and return the value they represent.
    def read_val(io)
      max_length = eval_param(:max_length)
      str = ""
      i = 0
      ch = nil

      # read until zero byte or we have read in the max number of bytes
      while ch != "\0" and i != max_length
        ch = io.readbytes(1)
        str << ch
        i += 1
      end

      zero_terminate(str, max_length)
    end

    # Returns an empty string as default.
    def sensible_default
      ""
    end

    # Returns +str+ after it has been zero terminated.  The returned string
    # will not be longer than +max_length+.
    def zero_terminate(str, max_length = nil)
      # str must not be empty
      result = (str == "") ? "\0" : str

      # remove anything after the first \0
      result = result.sub(/([^\0]*\0).*/, '\1')

      # trim string to be no longer than max_length including zero byte
      if max_length
        max_length = 1 if max_length < 1
        result = result[0, max_length]
        if result.length == max_length and result[-1, 1] != "\0"
          result[-1, 1] = "\0"
        end
      end

      # ensure last byte in the string is a zero byte
      result << "\0" if result[-1, 1] != "\0"

      result
    end
  end
end