require 'bit-struct/bit-struct'

class BitStruct
  # Class for floats (single and double precision) in network order.
  # Declared with BitStruct.float.
  class FloatField < Field
    # Used in describe.
    def self.class_name
      @class_name ||= "float"
    end
    
    def add_accessors_to(cl, attr = name) # :nodoc:
      unless offset % 8 == 0
        raise ArgumentError,
          "Bad offset, #{offset}, for #{self.class} #{name}." +
          " Must be multiple of 8."
      end
      
      unless length == 32 or length == 64
        raise ArgumentError,
          "Bad length, #{length}, for #{self.class} #{name}." +
          " Must be 32 or 64."
      end
      
      offset_byte = offset / 8
      length_byte = length / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte

      endian = (options[:endian] || options["endian"]).to_s
      case endian
      when "native"
        ctl = case length
          when 32; "f"
          when 64; "d"
        end
      when "little"
        ctl = case length
          when 32; "e"
          when 64; "E"
        end
      when "network", "big", ""
        ctl = case length
          when 32; "g"
          when 64; "G"
        end
      else
        raise ArgumentError,
          "Unrecognized endian option: #{endian.inspect}"
      end
      
      cl.class_eval do
        define_method attr do ||
          self[byte_range].unpack(ctl).first
        end

        define_method "#{attr}=" do |val|
          self[byte_range] = [val].pack(ctl)
        end
      end
    end
  end

  class << self
    # Define a floating point field in the current subclass of BitStruct,
    # with the given _name_ and _length_ (in bits).
    #
    # If a class is provided, use it for the Field class.
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    # The <tt>:endian => :native</tt> option overrides the default of
    # <tt>:network</tt> byte ordering, in favor of native byte ordering. Also
    # permitted are <tt>:big</tt> (same as <tt>:network</tt>) and
    # <tt>:little</tt>.
    #
    def float name, length, *rest
      opts = parse_options(rest, name, FloatField)
      add_field(name, length, opts)
    end
  end
end
