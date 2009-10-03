class BitStruct
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
    BitStruct.autoload :CharField, "bit-struct/char-field"

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
    BitStruct.autoload :FloatField, "bit-struct/float-field"

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
    BitStruct.autoload :HexOctetField, "bit-struct/hex-octet-field"

    # Define a nested field in the current subclass of BitStruct,
    # with the given _name_ and _nested_class_. Length is determined from
    # _nested_class_.
    #
    # If a class is provided, use it for the Field class (i.e. <=NestedField).
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    # For example:
    #
    #   class Sub < BitStruct
    #     unsigned :x,    8
    #   end
    #
    #   class A < BitStruct
    #     nest    :n,  Sub
    #   end
    #
    #   a = A.new
    #
    #   p a  # ==> #<A n=#<Sub x=0>>
    #
    # If a block is given, use it to define the nested fields. For example, the
    # following is equivalent to the above example:
    #
    #   class A < BitStruct
    #     nest :n do
    #       unsigned :x, 8
    #     end
    #   end
    #
    # WARNING: the accessors have COPY semantics, not reference. When you call a
    # reader method to get the nested structure, you get a *copy* of that data.
    # Expressed in terms of the examples above:
    #
    #   # This fails to set x in a.
    #   a.n.x = 3
    #   p a  # ==> #<A n=#<Sub x=0>>
    #
    #   # This works
    #   n = a.n
    #   n.x = 3
    #   a.n = n
    #   p a  # ==> #<A n=#<Sub x=3>>
    # 
    def nest(name, *rest, &block)
      nested_class = rest.grep(Class).find {|cl| cl <= BitStruct}
      rest.delete nested_class
      opts = parse_options(rest, name, NestedField)
      nested_class = opts[:nested_class] ||= nested_class
      
      unless (block and not nested_class) or (nested_class and not block)
        raise ArgumentError,
          "nested field must have either a nested_class option or a block," +
          " but not both"
      end
      
      unless nested_class
        nested_class = Class.new(BitStruct)
        nested_class.class_eval(&block)
      end
      
      opts[:default] ||= nested_class.initial_value.dup
      opts[:nested_class] = nested_class
      field = add_field(name, nested_class.bit_length, opts)
      field
    end
    alias struct nest
    BitStruct.autoload :NestedField, "bit-struct/nested-field"

    # Define an octet string field in the current subclass of BitStruct,
    # with the given _name_ and _length_ (in bits). Trailing nulls are
    # not considered part of the string. The field is accessed using
    # period-separated decimal digits.
    #
    # If a class is provided, use it for the Field class.
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    def octets(name, length, *rest)
      opts = parse_options(rest, name, OctetField)
      add_field(name, length, opts)
    end
    BitStruct.autoload :OctetField, "bit-struct/octet-field"

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
    BitStruct.autoload :PadField, "bit-struct/pad-field"

    # Define a signed integer field in the current subclass of BitStruct,
    # with the given _name_ and _length_ (in bits).
    #
    # If a class is provided, use it for the Field class.
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    # SignedField adds the <tt>:fixed => divisor</tt> option, which specifies
    # that the internally stored value is interpreted as a fixed point real
    # number with the specified +divisor+.
    #
    # The <tt>:endian => :native</tt> option overrides the default of
    # <tt>:network</tt> byte ordering, in favor of native byte ordering. Also
    # permitted are <tt>:big</tt> (same as <tt>:network</tt>) and
    # <tt>:little</tt>.
    #
    def signed name, length, *rest
      opts = parse_options(rest, name, SignedField)
      add_field(name, length, opts)
    end
    BitStruct.autoload :SignedField, "bit-struct/signed-field"

    # Define a printable text string field in the current subclass of BitStruct,
    # with the given _name_ and _length_ (in bits). Trailing nulls are
    # _not_ considered part of the string.
    #
    # If a class is provided, use it for the Field class.
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    # Note that the accessors have COPY semantics, not reference.
    #
    def text(name, length, *rest)
      opts = parse_options(rest, name, TextField)
      add_field(name, length, opts)
    end
    BitStruct.autoload :TextField, "bit-struct/text-field"

    # Define a unsigned integer field in the current subclass of BitStruct,
    # with the given _name_ and _length_ (in bits).
    #
    # If a class is provided, use it for the Field class.
    # If a string is provided, use it for the display_name.
    # If a hash is provided, use it for options.
    #
    # UnsignedField adds the <tt>:fixed => divisor</tt> option, which specifies
    # that the internally stored value is interpreted as a fixed point real
    # number with the specified +divisor+.
    #
    # The <tt>:endian => :native</tt> option overrides the default of
    # <tt>:network</tt> byte ordering, in favor of native byte ordering. Also
    # permitted are <tt>:big</tt> (same as <tt>:network</tt>) and
    # <tt>:little</tt>.
    #
    def unsigned name, length, *rest
      opts = parse_options(rest, name, UnsignedField)
      add_field(name, length, opts)
    end
    BitStruct.autoload :UnsignedField, "bit-struct/unsigned-field"

    # Define a vector field in the current subclass of BitStruct,
    # with the given _name_.
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
    # If a number is provided, use it for length (equivalent to using the
    # :length option).
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
      
      length = opts[:length] || rest.grep(Integer).first
        ## what about :length => :lenfield
      unless length
        raise ArgumentError,
          "Must provide length as argument N or as option :length => N"
      end

      opts[:default] ||= vector_class.new(length) ## nil if variable length
      opts[:vector_class] = vector_class
      
      bit_length = vector_class.struct_class.round_byte_length * 8 * length
      
      field = add_field(name, bit_length, opts)
      field
    end
    BitStruct.autoload :VectorField, "bit-struct/vector-field"
  end
  
  autoload :Vector, "bit-struct/vector"
end
