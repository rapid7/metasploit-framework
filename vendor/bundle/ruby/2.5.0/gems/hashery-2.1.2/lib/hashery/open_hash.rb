require 'hashery/crud_hash'

module Hashery

  # OpenHash is a Hash, but also supports open properties much like
  # OpenStruct.
  #
  # Only names that are name methods of Hash can be used as open slots.
  # To open a slot for a name that would otherwise be a method, the 
  # method needs to be made private. The `#open!` method can be used
  # to handle this.
  #
  # Examples
  #
  #     o = OpenHash.new
  #     o.open!(:send)
  #     o.send = 4
  #
  class OpenHash < CRUDHash

    alias :object_class :class

    #FILTER  = /(^__|^\W|^instance_|^object_|^to_)/
    #methods = Hash.instance_methods(true).select{ |m| m !~ FILTER }
    #methods = methods - [:each, :inspect, :send]  # :class, :as]
    #private *methods

    #
    # Initialize new OpenHash instance.
    #
    # TODO: Maybe `safe` should be the first argument?
    #
    def initialize(default=nil, safe=false, &block)
      @safe = safe
      super(*[default].compact, &block)
    end

    #
    # If safe is set to true, then public methods cannot be overriden
    # by hash keys.
    #
    attr_accessor :safe

    #
    # Alias to original store method.
    #
    #alias :store! :store

    #
    # Index `value` to `key`. Unless safe mode, will also open up the 
    # key if it is not already open.
    #
    # key   - Index key to associate with value.
    # value - Value to be associate with key.
    #
    # Returns +value+.
    #
    def store(key, value)
      #open!(key)
      super(key, value)
    end

    #
    # Open up a slot that that would normally be a Hash method.
    #
    # The only methods that can't be opened are ones starting with `__`.
    #
    # methods - [Array<String,Symbol>] method names
    #
    # Returns Array of slot names that were opened.
    #
    def open!(*methods)
      # Only select string and symbols, any other type of key is allowed,
      # it just won't be accessible via dynamic methods.
      methods = methods.select{ |x| String === x || Symbol === x }
      if methods.any?{ |m| m.to_s.start_with?('__') }
        raise ArgumentError, "cannot open shadow methods"
      end
      # only public methods need be made protected
      methods = methods.map{ |x| x.to_sym }
      methods = methods & public_methods(true).map{ |x| x.to_sym }
      if @safe
        raise ArgumentError, "cannot set public method" unless methods.empty?
      else
        (class << self; self; end).class_eval{ protected *methods }
      end
      methods
    end

    # @deprecated
    alias :omit! :open!

    #
    # Is a slot open?
    #
    # method - [String,Symbol] method name
    #
    # Returns `true` or `false`.
    #
    def open?(method)
      methods = public_methods(true).map{ |m| m.to_sym }
      ! methods.include?(method.to_sym)
    end

    #
    # Make specific Hash methods available for use that have previously opened.
    #
    # methods - [Array<String,Symbol>] method names
    #
    # Returns +methods+.
    #
    def close!(*methods)
      (class << self; self; end).class_eval{ public *methods }
      methods
    end

    #
    #
    #
    def method_missing(s,*a, &b)
      type = s.to_s[-1,1]
      name = s.to_s.sub(/[!?=]$/, '')
      key  = name.to_sym

      case type
      when '='
        store(key, a.first)
      when '?'
        key?(key)
      when '!'
        # call an underlying private method
        # TODO: limit this to omitted methods (from included) ?
        __send__(name, *a, &b)
      else
        #if key?(key)
          retrieve(key)
        #else
        #  super(s,*a,&b)
        #end
      end
    end

  end

end
