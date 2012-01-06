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
end
