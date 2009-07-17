require 'bit-struct/bit-struct'

class BitStruct
  # Class for fixed length binary strings of characters.
  # Declared with BitStruct.char.
  class CharField < Field
    #def self.default
    #  don't define this, since it must specify N nulls and we don't know N
    #end
    
    # Used in describe.
    def self.class_name
      @class_name ||= "char"
    end

    def add_accessors_to(cl, attr = name) # :nodoc:
      unless offset % 8 == 0
        raise ArgumentError,
          "Bad offset, #{offset}, for #{self.class} #{name}." +
          " Must be multiple of 8."
      end
      
      unless length % 8 == 0
        raise ArgumentError,
          "Bad length, #{length}, for #{self.class} #{name}." +
          " Must be multiple of 8."
      end
      
      offset_byte = offset / 8
      length_byte = length / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte
      val_byte_range = 0..length_byte-1

      cl.class_eval do
        define_method attr do ||
          self[byte_range].to_s
        end

        define_method "#{attr}=" do |val|
          val = val.to_s
          if val.length < length_byte
            val += "\0" * (length_byte - val.length)
          end
          self[byte_range] = val[val_byte_range]
        end
      end
    end
  end
  
  class << self
    # Define a char string field in the current subclass of BitStruct,
    # with the given _name_ and _length_ (in bits). Trailing nulls _are_
    # considered part of the string.
    #
    # If a class is provided, use it for the Field class.
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    # Note that the accessors have COPY semantics, not reference.
    #
    def char(name, length, *rest)
      opts = parse_options(rest, name, CharField)
      add_field(name, length, opts)
    end
    alias string char
  end
end
