require 'hashery/open_hash'

module Hashery

  # OpenCascade is subclass of OpenHash. It differs in a few
  # significant ways. The reason this class is called "cascade" is that
  # every internal Hash is transformed into an OpenCascade dynamically
  # upon access. This makes it easy to create "cascading" references.
  #
  #   h = { :x => { :y => { :z => 1 } } }
  #   c = OpenCascade[h]
  #   c.x.y.z  #=> 1
  #
  # As soon as you access a node it automatically becomes an OpenCascade.
  #
  #   c = OpenCascade.new   #=> #<OpenCascade:0x7fac3680ccf0 {}>
  #   c.r                   #=> #<OpenCascade:0x7fac368084c0 {}>
  #   c.a.b                 #=> #<OpenCascade:0x7fac3680a4f0 {}>
  #
  # But if you set a node, then that will be that value.
  #
  #   c.a.b = 4             #=> 4
  #
  # To query a node without causing the auto-creation of an OpenCasade
  # instance, use the `?`-mark.
  #
  #   c.a.z?                #=> nil
  #
  # OpenCascade also transforms Hashes within Arrays.
  #
  #   h = { :x=>[ {:a=>1}, {:a=>2} ], :y=>1 }
  #   c = OpenCascade[h]
  #   c.x.first.a.assert == 1
  #   c.x.last.a.assert  == 2
  #
  # Finally, you can set call a private method via bang methods using the `!`-mark.
  #
  #   c = OpenCascade.new   #=> #<OpenCascade:0x7fac3680ccf0 {}>
  #   c.each = 4
  #   c.each! do |k,v|
  #     ...
  #   end
  #
  #   c.x!(4).y!(3)         #=> #<OpenCascade:0x7fac3680ccf0 {:x=>4, :y=>3}>
  #
  # Subclassing OpenCascade with cause the new subclass to become the class that
  # is auto-created. If this is not the behavior desired, consider using delegation
  # instead of subclassing.
  #
  class OpenCascade < OpenHash

    #
    #def self.[](hash)
    #  oc = new
    #  hash.each{ |(k,v)| oc.store(k,v) }
    #  oc
    #end

    #
    # Initialize new OpenCascade instance.
    #
    # default - The usual default object.
    #
    def initialize(*default)
      @read = {}

      leet = lambda { |h,k| h[k] = self.class.new(&leet) }
      super(*default, &leet)
    end

    #
    # Alias for original read method.
    #
    alias :retrieve! :retrieve

    #
    # Read value given a +key+.
    #
    # key - Index key to lookup.
    #
    # Returns value.
    #
    def retrieve(key)
      ckey = cast_key(key)
      if @read[ckey]
        super(key)
      else
        @read[ckey] = store(key, cast_value(super(key)))
      end
    end

    #
    #
    #
    def method_missing(sym, *args, &blk)
      type = sym.to_s[-1,1]
      name = sym.to_s.gsub(/[=!?]$/, '').to_sym

      case type
      when '='
        store(name, args.first)
      when '?'
        key?(name) ? retrieve!(name) : nil    # key?(name)
      when '!'
        __send__(name, *args, &blk)
      else
        #if key?(name)
          retrieve(name)
        #else
        #  #default = OpenCascade.new #self.class.new
        #  #default = default_proc ? default_proc.call(self, name) : default
        #  store(name, read(name))
        #end
      end
    end

    def respond_to?(sym, include_private = false)
      sym != :to_ary && super
    end

    #def each
    #  super do |key, entry|
    #    yield([key, transform_entry(entry)])
    #  end
    #end

  private

    #
    # Cast value, such that Hashes are converted to OpenCascades.
    # And Hashes in Arrays are converted to OpenCascades as well.
    #
    def cast_value(entry)
      case entry
      when Hash
        e = OpenCascade.new
        e.key_proc = key_proc if key_proc
        e.merge!(entry)
        e
      when Array
        entry.map{ |e| cast_value(e) }
      else
        entry
      end
    end

  end

end


#--
# Last, when an entry is not found, 'null' is returned rather then 'nil'.
# This allows for run-on entries withuot error. Eg.
#
#   o = OpenCascade.new
#   o.a.b.c  #=> null
#
# Unfortuately this requires an explict test for null? in 'if' conditions.
#
#   if o.a.b.c.null?  # true if null
#   if o.a.b.c.nil?   # true if nil or null
#   if o.a.b.c.not?   # true if nil or null or false
#
# So be sure to take that into account.
#++

