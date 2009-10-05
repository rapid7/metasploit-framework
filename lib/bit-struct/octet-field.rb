require 'bit-struct/char-field'

class BitStruct
  # Class for char fields that can be accessed with values like
  # "xxx.xxx.xxx.xxx", where each xxx is up to 3 decimal digits representing a
  # single octet. The original string-based accessors are still available with
  # the <tt>_chars</tt> suffix.
  # 
  # Declared with BitStruct.octets.
  class OctetField < BitStruct::CharField
    # Used in describe.
    def self.class_name
      @class_name ||= "octets"
    end
    
    SEPARATOR = "."
    FORMAT    = "%d"
    BASE      = 10

    def add_accessors_to(cl, attr = name) # :nodoc:
      attr_chars = "#{attr}_chars"
      super(cl, attr_chars)
      sep   = self.class::SEPARATOR
      base  = self.class::BASE
      fmt   = self.class::FORMAT
      
      cl.class_eval do
        define_method attr do ||
          ary = []
          send(attr_chars).each_byte do  |c|
            ary << fmt % c
          end
          ary.join(sep)
        end
        
        old_writer = "#{attr_chars}="

        define_method "#{attr}=" do |val|
          data = val.split(sep).map{|s|s.to_i(base)}.pack("C*")
          send(old_writer, data)
        end
      end
    end
  end
end
