require 'hashery/crud_hash'

module Hashery

  # A PropertyHash is the same as a regular Hash except it strictly limits the
  # allowed keys.
  #
  # There are two ways to use it.
  #
  # 1) As an object in itself.
  #
  #   h = PropertyHash.new(:a=>1, :b=>2)
  #   h[:a]        #=> 1
  #   h[:a] = 3
  #   h[:a]        #=> 3
  #
  # But if we try to set key that was not fixed, then we will get an error.
  #
  #   h[:x] = 5    #=> ArgumentError
  # 
  # 2) As a superclass.
  #
  #   class MyPropertyHash < PropertyHash
  #     property :a, :default => 1
  #     property :b, :default => 2
  #   end
  #
  #   h = MyPropertyHash.new
  #   h[:a]        #=> 1
  #   h[:a] = 3
  #   h[:a]        #=> 3
  #
  # Again, if we try to set key that was not fixed, then we will get an error.
  #
  #   h[:x] = 5    #=> ArgumentError
  #
  class PropertyHash < CRUDHash

    #
    # Get a list of properties with default values.
    #
    # Returns [Hash] of properties and their default values.
    #
    def self.properties
      @properties ||= (
        parent = ancestors[1]
        if parent.respond_to?(:properties)
          parent.properties
        else
          {}
        end
      )
    end

    #
    # Define a property.
    #
    # key  - Name of property.
    # opts - Property options.
    #        :default - Default value of property.
    #
    # Returns default value.
    #
    def self.property(key, opts={})
      properties[key] = opts[:default]
    end

    #
    # Initialize new instance of PropertyHash.
    #
    # properties   - [Hash] Priming properties with default values, or
    #                if it doesn't respond to #each_pair, a default object.
    # default_proc - [Proc] Procedure for default value of properties
    #                for properties without specific defaults.
    #
    def initialize(properties={}, &default_proc)
      if properties.respond_to?(:each_pair)
        super(&default_proc)
        fixed = self.class.properties.merge(properties)
        fixed.each_pair do |key, value|
          store!(key, value)
        end
      else
        super(*[properties].compact, &default_proc)
      end
    end

    # Alias original #store method and make private.
    alias :store! :store
    private :store!

    #
    # Create a new property, on-the-fly.
    #
    # key  - Name of property.
    # opts - Property options.
    #        :default - Default value of property.
    #
    # Returns default value.
    #
    def property(key, opts={})
      if opts[:default]
        store!(key, opts[:default])
      else
        store!(key, retrieve(key))
      end
    end

    #
    # Store key value pair, ensuring the key is a valid property first.
    #
    # key   - The `Object` to act as indexing key.
    # value - The `Object` to associate with key.
    #
    # Raises ArgumentError if key is not a valid property.
    #
    # Returns +value+.
    #
    def store(key, value)
      assert_key!(key)
      super(key, value)
    end

    #
    #def update(h)
    #  h.keys.each{ |k| assert_key!(k) }
    #  super(h)
    #end

    #
    #def merge!(h)
    #  h.keys.each{ |k| assert_key!(k) }
    #  super(h)
    #end

    #
    # Like #store but takes a two-element Array of `[key, value]`.
    #
    # Returns value.
    #
    #def <<(a)
    #  k,v = *a
    #  store(k,v)
    #end

  private

    #
    # Asserta that a key is a defined property.
    #
    # Raises ArgumentError if key is not a property.
    #
    def assert_key!(key)
      unless key?(key)
        raise ArgumentError, "property is not defined -- #{key.inspect}"
      end
    end

  end

end
