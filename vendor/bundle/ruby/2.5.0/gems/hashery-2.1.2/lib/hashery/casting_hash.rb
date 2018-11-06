require 'hashery/crud_hash'

module Hashery

  # CastingHash is just like CRUDHash, except that both keys and values
  # can be passed through casting procedures.
  #
  class CastingHash < CRUDHash

    #
    # Like `#new` but can take a priming Hash or Array-pairs.
    #
    # hash - Hash-like object.
    #
    # Examples
    #
    #   CastingHash[:a,1,:b,2]
    #
    # Returns `CastingHash`.
    #
    def self.[](hash)
      s = new
      hash.each{ |k,v| s[k] = v }
      s
    end

    #
    # Unlike traditional Hash a CastingHash's block argument
    # coerces key/value pairs when #store is called.
    #
    # default   - Default value.
    # cast_proc - Casting procedure.
    #
    def initialize(default=nil, &cast_proc)
      @cast_proc = cast_proc
      super(default, &nil)
    end

    #
    # The cast procedure.
    #
    # proc - Casting procedure.
    #
    # Returns `Proc` used for casting.
    #
    def cast_proc(&proc)
      @cast_proc = proc if proc
      @cast_proc
    end

    #
    # Set `cast_proc`. This procedure must take two arguments (`key, value`)
    # and return the same.
    #
    # proc - Casting procedure.
    #
    # Returns +proc+.
    #
    def cast_proc=(proc)
      raise ArgumentError unless Proc === proc or NilClass === proc
      @cast_proc = proc
    end

    #
    # CRUD method for create and update. Unlike the parent class
    # the key, value pair are passed threw the cast_proc before
    # being set in the underlying hash table.
    #
    # key   - Key of entry.
    # value - Value of entry.
    #
    # Returns the +value+.
    #
    def store(key, value)
      super(*cast_pair(key, value))
    end

    #
    # Replace current entries with those from another Hash,
    # or Hash-like object. Each entry is run through the
    # casting procedure as it is added.
    #
    # other - Hash-like object.
    #
    # Returns +self+.
    # 
    def replace(other)
      super cast(other)
    end

    #
    # Convert the CastingHash to a regular Hash.
    #
    # Returns an ordinary `Hash`.
    #
    def to_hash
      h = {}; each{ |k,v| h[k] = v }; h
    end

    #
    # Returns an ordinary `Hash`.
    #
    alias_method :to_h, :to_hash

    #
    # Recast all entries via the cast procedure.
    #
    # TODO: Isn't this the same as `#rehash`?
    #
    # Returns +self+.
    #
    def recast!
      replace self
    end

  private

    #
    # If `cast_proc` is defined then use it to process key-value pair,
    # otherwise return them as is.
    #
    # key   - Key of entry.
    # value - Value of entry.
    #
    # Returns `Array` of key-value pair.
    #
    def cast_pair(key, value)
      if cast_proc
        return cast_proc.call(key, value)
      else
        return key, value
      end
    end

    #
    # Cast a given +hash+ according to the `#key_proc` and `#value_proc`.
    #
    # hash - A `Hash` or anything the responds to `#each` like a hash.
    #
    # Returns a recasted `Hash`.
    #
    def cast(hash)
      h = {}
      hash.each do |k,v|
        k, v = cast_pair(k, v)
        h[k] = v
      end
      h
    end

  end

end

# TODO: Should we add #to_casting_hash to Hash classs?

#class Hash
#
#  # Convert a Hash to a CastingHash.
#  def to_casting_hash(value_cast=nil, &key_cast)
#    CastingHash.new(self, value_cast, &key_cast)
#  end
#
#end
