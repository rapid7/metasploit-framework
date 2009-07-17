require 'bit-struct/bit-struct'

class BitStruct
  # Class for fixed length padding.
  class PadField < Field
    # Used in describe.
    def self.class_name
      @class_name ||= "padding"
    end

    def add_accessors_to(cl, attr = name) # :nodoc:
      # No accessors for padding.
    end

    def inspectable?; false; end
  end
  
  class << self
    # Define a padding field in the current subclass of BitStruct,
    # with the given _name_ and _length_ (in bits).
    #
    # If a class is provided, use it for the Field class.
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    def pad(name, length, *rest)
      opts = parse_options(rest, name, PadField)
      add_field(name, length, opts)
    end
    alias padding pad
  end
end
