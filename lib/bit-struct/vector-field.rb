require 'bit-struct/vector'

class BitStruct
  # Class for embedding a BitStruct::Vector as a field within a BitStruct.
  # Declared with BitStruct.vector.
  class VectorField < Field
    # Used in describe.
    def self.class_name
      @class_name ||= "vector"
    end
    
    # Used in describe.
    def class_name
      @class_name ||= vector_class.name[/\w+$/]
    end
    
    # Returns the subclass of Vector that is used to manage the value of this
    # field. If the class was specified in the BitStruct.vector declaration,
    # #vector_class will return it, otherwise it will be an anonymous class
    # (which you can assign to a constant to make nonymous ;).
    def vector_class
      @vector_class ||= options[:vector_class] || options["vector_class"]
    end

    def describe opts # :nodoc:
      if opts[:expand]
        opts = opts.dup
        opts[:byte_offset] = offset / 8
        opts[:omit_header] = opts[:omit_footer] = true
        vector_class.describe(nil, opts) {|desc| yield desc}
      else
        super
      end
    end

    def add_accessors_to(cl, attr = name) # :nodoc:
      unless offset % 8 == 0
        raise ArgumentError,
          "Bad offset, #{offset}, for vector field #{name}." +
          " Must be multiple of 8."
      end
      
      unless length % 8 == 0
        raise ArgumentError,
          "Bad length, #{length}, for vector field #{name}." +
          " Must be multiple of 8."
      end
      
      offset_byte = offset / 8
      length_byte = length / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte

      vc = vector_class
      
      cl.class_eval do
        define_method attr do ||
          vc.new(self[byte_range])
        end

        define_method "#{attr}=" do |val|
          if val.length != length_byte
            raise ArgumentError, "Size mismatch in vector field assignment " +
              "to #{attr} with value #{val.inspect}"
          end
          
          if val.class != vc
            warn "Type mismatch in vector field assignment " +
              "to #{attr} with value #{val.inspect}"
          end
          
          self[byte_range] = val
        end
      end
    end
  end
end
