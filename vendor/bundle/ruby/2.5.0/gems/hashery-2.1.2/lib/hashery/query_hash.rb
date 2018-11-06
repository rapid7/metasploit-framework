module Hashery

  require 'hashery/key_hash'

  # QueryHash is essentially a Hash class, but with some OpenStruct-like features.
  #
  #     q = QueryHash.new
  #
  # Entries can be added to the Hash via a setter method.
  #
  #     q.a = 1
  #
  # Then looked up via a query method.
  #
  #     q.a?  #=> 1
  #
  # The can also be looked up via a bang method.
  # 
  #     q.a!  #=> 1
  #
  # The difference between query methods and bang methods is that the bang method
  # will auto-instantiate the entry if not present, where as a query method will not.
  #
  # A QueryHash might not be quite as elegant as an OpenHash in that reader
  # methods must end in `?` or `!`, but it remains fully compatible with Hash
  # regardless of it's settings.
  #
  class QueryHash < CRUDHash

    #
    # By default the `key_proc` is set to convert all keys to strings via `#to_s`.
    #
    # default      - Default object, or
    # default_proc - Default procedure.
    #
    def initialize(*default, &default_proc)
      @key_proc = Proc.new{ |k| k.to_s }
      super(*default, &default_proc)
    end

    #
    # Route get and set calls.
    #
    # s - [Symbol] Name of method.
    # a - [Array] Method arguments.
    # b - [Proc] Block argument.
    #
    # Examples
    #
    #   o = QueryHash.new
    #   o.a = 1
    #   o.a?  #=> 1
    #   o.b?  #=> nil
    #
    def method_missing(s,*a, &b)
      type = s.to_s[-1,1]
      name = s.to_s.sub(/[!?=]$/, '')     
      key  = name  #key  = cast_key(name)

      case type
      when '='
        store(key, a.first)
      when '!'
        default = (default_proc ? default_proc.call(self, key) : default)
        key?(key) ?  fetch(key) : store(key, default)
      when '?'
        key?(key) ? fetch(key) : nil
      else
        # return self[key] if key?(key)
        super(s,*a,&b)
      end
    end

    #
    # Custom #respond_to to account for #method_missing.
    #
    # name - The method name to check.
    #
    # Returns `true` or `false`.
    #
    def respond_to?(name)
      return true if name.to_s.end_with?('=')
      return true if name.to_s.end_with?('?')
      return true if name.to_s.end_with?('!')
      #key?(name.to_sym) || super(name)
      super(name)
    end

  end

end
