require "bindata/single"

module BinData
  # Rest will consume the input stream from the current position to the end of
  # the stream.  This will mainly be useful for debugging and developing.
  #
  #   require 'bindata'
  #
  #   class A < BinData::MultiValue
  #     string :a, :read_length => 5
  #     rest   :rest
  #   end
  #
  #   obj = A.read("abcdefghij")
  #   obj.a #=> "abcde"
  #   obj.rest #=" "fghij"
  #
  class Rest < BinData::Single

    # Register this class
    register(self.name, self)

    #---------------
    private

    # Return the string representation that +val+ will take when written.
    def val_to_str(val)
      val
    end

    # Read a number of bytes from +io+ and return the value they represent.
    def read_val(io)
      io.raw_io.read
    end

    # Returns an empty string as default.
    def sensible_default
      ""
    end
  end
end