require 'bit-struct/char-field'

class BitStruct
  # Class for char fields that can be accessed with values like
  # "xx:xx:xx:xx", where each xx is up to 2 hex digits representing a
  # single octet. The original string-based accessors are still available with
  # the <tt>_chars</tt> suffix.
  # 
  # Declared with BitStruct.hex_octets.
  class HexOctetField < BitStruct::OctetField
    # Used in describe.
    def self.class_name
      @class_name ||= "hex_octets"
    end
    
    SEPARATOR = ":"
    FORMAT    = "%02x"
    BASE      = 16
  end
  
  class << self
    # Define an octet string field in the current subclass of BitStruct,
    # with the given _name_ and _length_ (in bits). Trailing nulls are
    # not considered part of the string. The field is accessed using
    # period-separated hex digits.
    #
    # If a class is provided, use it for the Field class.
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    def hex_octets(name, length, *rest)
      opts = parse_options(rest, name, HexOctetField)
      add_field(name, length, opts)
    end
  end
end
