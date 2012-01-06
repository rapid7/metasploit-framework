# A Vector is, like a BitStruct, a String. It retains all of the String
# methods, except for #[], #[]=, and #each. These methods operate on entries
# instead of chars. Other methods, including #length and #slice, are unchanged.
# Hence a Vector can be used directly with sockets, binary files, etc.
#
# Note that Vector is not a subclass of BitStruct. It cannot be used in
# a #nest declaration in a BitStruct. Instead, use the #vector declaration.
# See BitStruct::VectorField.
#
# Different instances of the same Vector class may have different lengths, and
# a single instance can change its length. The length should always be a
# multiple of the struct size.
class BitStruct::Vector < String
  include Enumerable

  @default_options = {}
  @struct_class = nil

  class << self
    def inherited cl
      cl.instance_eval do
        @struct_class = nil
      end
    end
    
    # Called as a class method with a single argument in a user-defined
    # subclass to specify a particular BitStruct class to use for each entry,
    # instead of generating an anonymous class. Called without arguments to
    # access the struct class, generating an anonymous one if needed.
    # The struct_class inherits from the struct_class of the parent Vector
    # class.
    def struct_class cl = nil
      if cl
        if @struct_class
          warn "changing struct_class in #{self} to #{cl}"
        end
        @struct_class = cl
        @struct_class.default_options default_options
      else
        unless @struct_class
          @struct_class = self == BitStruct::Vector ? BitStruct : 
            Class.new(superclass.struct_class)
          @struct_class.default_options default_options
        end
      end
      @struct_class
    end

    def method_missing(*a, &block)  # :nodoc:
      struct_class.send(*a, &block)
    end

    alias :orig_respond_to? :respond_to?
    def respond_to?(*m)  # :nodoc:
      orig_respond_to?(*m) || struct_class.respond_to?(*m)
    end
    
    # Get or set the hash of default options for the class, which apply to all
    # fields in the entries. If +h+ is provided, update the default options
    # with that hash. Default options are inherited.
    #
    # This is especially useful with the <tt>:endian => val</tt> option.
    def default_options h = nil
      @default_options ||= superclass.default_options.dup
      if h
        @default_options.merge! h
        if @struct_class
          @struct_class.default_options h
        end
      end
      @default_options
    end
    
    def describe(*args)
      fmt = args[0] || BitStruct.describe_format
      if block_given?
        struct_class.describe(*args){|desc| yield desc}
        yield ["..."]*5
      else
        struct_class.describe(*args) + [fmt % (["..."]*5)]
      end
    end
  end
    
  # Convenience method for instances. Returns the BitStruct class that
  # describes each entry.
  def struct_class
    self.class.struct_class
  end
  
  # Convenience method for instances. Returns the string length in bytes of 
  # each entry in the vector.
  def struct_class_length
    self.class.struct_class.round_byte_length
  end
  
  # +arg+ can be an integer (number of entries) or a string
  # (binary data, such as another Vector of the same size).
  def initialize arg   # :yields: instance
    case arg
    when Integer
      super(struct_class.initial_value * arg)
    
    else
      begin
        super arg
      rescue NameError
        raise ArgumentError, "must be string or integer: #{arg.inspect}"
      end
    end 

    yield self if block_given?
  end
  
  # Get the +i+-th entry. Returns a *copy* of the entry. If you want to
  # use this copy to modify the entry, you must modify the copy and then
  # use #[]= to replace the entry with the copy.
  def [](i)
    sc = self.class.struct_class
    entry_length = sc.round_byte_length

    unless (0...(length / entry_length)).include? i
      raise ArgumentError, "index out of range: #{i}"
    end
    
    sc.new slice(entry_length * i, entry_length)
  end
  
  alias _old_replace_substr []=

  # Set the +i+-th entry to +val+.
  def []=(i,val)
    entry_length = struct_class_length
    
    unless (0...(length / entry_length)).include? i
      raise ArgumentError, "index out of range: #{i}"
    end
    
    unless val.length == entry_length
      raise ArgumentError, "wrong entry length: #{val.length} != #{entry_length}"
    end
    
    _old_replace_substr(entry_length * i, entry_length, val)
  end
  
  ## TODO: [i..j] etc.
  
  # Iterate over entries.
  def each
    entry_length = struct_class_length
    (length / entry_length).times do |i|
      yield self[i]
    end
  end
  
  def inspect(opts = BitStruct::DEFAULT_INSPECT_OPTS)
    if opts[:include_class]
      opts = opts.dup
      opts[:include_class] = false
      s = self.class.inspect + ": "
    else
      s = ""
    end
    
    s << entries.map{|entry| entry.inspect(opts)}.join(opts[:separator])
    lb, rb = opts[:brackets]
    [lb, s, rb].join
  end
  
  def inspect_detailed
    inspect(BitStruct::DETAILED_INSPECT_OPTS)
  end
end
