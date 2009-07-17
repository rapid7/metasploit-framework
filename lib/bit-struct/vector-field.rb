require 'bit-struct/vector'

class BitStruct
  # Class for embedding a BitStruct::Vector as a field within a BitStruct.
  # Declared with BitStruct.vector.
  class VectorField < Field
    def initialize(*args)
      super
    end
    
    # Used in describe.
    def self.class_name
      @class_name ||= "vector"
    end
    
    def class_name
      @class_name ||= vector_class.name[/\w+$/]
    end
    
    def vector_class
      @vector_class ||= options[:vector_class] || options["vector_class"]
    end

    def describe opts
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
  
  class << self
    # Define a vector field in the current subclass of BitStruct,
    # with the given _name_.
    #
    # In _rest_:
    #
    # If a class is provided, use it for the Vector class, otherwise
    # the block must define the entry fields. The two forms looks like
    # this:
    #
    #   class Vec < BitStruct::Vector
    #     # these declarations apply to *each* entry in the vector:
    #     unsigned :x,  16
    #     signed   :y,  32
    #   end
    #
    #   class Packet < BitStruct
    #     # Using the Vec class defined above
    #     vector  :v, Vec, "a vector", :length => 5
    #
    #     # equivalently, using an anonymous subclass of BitStruct::Vector
    #     vector :v2, "a vector", :length => 5 do
    #       unsigned :x,  16
    #       signed   :y,  32
    #     end
    #   end
    #
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    # WARNING: the accessors have COPY semantics, not reference. When you call a
    # reader method to get the vector structure, you get a *copy* of that data.
    #
    # For example, to modify the numeric fields in a Packet as defined above:
    #
    #   pkt = Packet.new
    #     vec = pkt.v
    #       entry = vec[2]
    #         entry.x = 123
    #         entry.y = -456
    #       vec[2] = entry
    #     pkt.v = vec
    # 
    def vector(name, *rest, &block)
      opts = parse_options(rest, name, nil)
      cl = opts[:field_class]
      opts[:field_class] = VectorField
      
      unless (block and not cl) or (cl and not block)
        raise ArgumentError,
          "vector must have either a class or a block, but not both"
      end
      
      case
      when cl == nil
        vector_class = Class.new(BitStruct::Vector)
        vector_class.class_eval(&block)

      when cl < BitStruct
        vector_class = Class.new(BitStruct::Vector)
        vector_class.struct_class cl

      when cl < BitStruct::Vector
        vector_class = cl
      
      else raise ArgumentError, "Bad vector class: #{cl.inspect}"
      end
      
      vector_class.default_options default_options
      
      length = opts[:length] ## what about :length => :lenfield
      unless length
        raise ArgumentError, "Must provide length as :length => N"
      end

      opts[:default] ||= vector_class.new(length) ## nil if variable length
      opts[:vector_class] = vector_class
      
      bit_length = vector_class.struct_class.round_byte_length * 8 * length
      
      field = add_field(name, bit_length, opts)
      field
    end
  end
end

__END__

# The above does not permit a Vector to be embedded in another
# BitStruct. Hypothetical syntax for doing so:

class Packet < BitStruct
  unsigned :stuff, 24, "whatever"
  
  # Using the Vec class defined above
  vector  :v, Vec, "a vector", :length => 5

  # equivalently, using an anonymous subclass of BitStruct::Vector
  vector :v, "a vector", :length => 5 do
    unsigned :x,  16
    signed   :y,  32
  end
end

