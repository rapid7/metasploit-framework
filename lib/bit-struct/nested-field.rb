require 'bit-struct/bit-struct'

class BitStruct
  # Class for nesting a BitStruct as a field within another BitStruct.
  # Declared with BitStruct.nest.
  class NestedField < Field
    def initialize(*args)
      super
    end
    
    # Used in describe.
    def self.class_name
      @class_name ||= "nest"
    end
    
    def class_name
      @class_name ||= nested_class.name[/\w+$/]
    end
    
    def nested_class
      @nested_class ||= options[:nested_class] || options["nested_class"]
    end

    def describe opts
      if opts[:expand]
        opts = opts.dup
        opts[:byte_offset] = offset / 8
        opts[:omit_header] = opts[:omit_footer] = true
        nested_class.describe(nil, opts) {|desc| yield desc}
      else
        super
      end
    end

    def add_accessors_to(cl, attr = name) # :nodoc:
      unless offset % 8 == 0
        raise ArgumentError,
          "Bad offset, #{offset}, for nested field #{name}." +
          " Must be multiple of 8."
      end
      
      unless length % 8 == 0
        raise ArgumentError,
          "Bad length, #{length}, for nested field #{name}." +
          " Must be multiple of 8."
      end
      
      offset_byte = offset / 8
      length_byte = length / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte

      nc = nested_class
      
      cl.class_eval do
        define_method attr do ||
          nc.new(self[byte_range])
        end

        define_method "#{attr}=" do |val|
          if val.length != length_byte
            raise ArgumentError, "Size mismatch in nested struct assignment " +
              "to #{attr} with value #{val.inspect}"
          end
          
          if val.class != nc
            warn "Type mismatch in nested struct assignment " +
              "to #{attr} with value #{val.inspect}"
          end
          
          self[byte_range] = val
        end
      end
    end
  end
end
