module Hashery

  # The Dictionary class is a Hash that preserves order.
  # So it has some array-like extensions also. By defualt
  # a Dictionary object preserves insertion order, but any
  # order can be specified including alphabetical key order.
  #
  # Using a Dictionary is almost the same as using a Hash.
  #
  #   # You can do simply
  #   hsh = Dictionary.new
  #   hsh['z'] = 1
  #   hsh['a'] = 2
  #   hsh['c'] = 3
  #   p hsh.keys     #=> ['z','a','c']
  #
  #   # or using Dictionary[] method
  #   hsh = Dictionary['z', 1, 'a', 2, 'c', 3]
  #   p hsh.keys     #=> ['z','a','c']
  #
  #   # but this don't preserve order
  #   hsh = Dictionary['z'=>1, 'a'=>2, 'c'=>3]
  #   p hsh.keys     #=> ['a','c','z']
  #
  #   # Dictionary has useful extensions: push, pop and unshift
  #   p hsh.push('to_end', 15)       #=> true, key added
  #   p hsh.push('to_end', 30)       #=> false, already - nothing happen
  #   p hsh.unshift('to_begin', 50)  #=> true, key added
  #   p hsh.unshift('to_begin', 60)  #=> false, already - nothing happen
  #   p hsh.keys                     #=> ["to_begin", "a", "c", "z", "to_end"]
  #   p hsh.pop                      #=> ["to_end", 15], if nothing remains, return nil
  #   p hsh.keys                     #=> ["to_begin", "a", "c", "z"]
  #   p hsh.shift                    #=> ["to_begin", 30], if nothing remains, return nil
  #
  # == Notes
  #
  # * You can use #order_by to set internal sort order.
  # * #<< takes a two element [k,v] array and inserts.
  # * Use ::auto which creates Dictionay sub-entries as needed.
  # * And ::alpha which creates a new Dictionary sorted by key.
  #
  # == Acknowledgments
  #
  # Dictionary is a port of OrderHash 2.0 Copyright (c) 2005 Jan Molic.
  #
  # People who have contributed to this class since then include:
  #
  # * Andrew Johnson (merge, to_a, inspect, shift and Hash[])
  # * Jeff Sharpe    (reverse and reverse!)
  # * Thomas Leitner (has_key? and key?)
  #
  # OrderedHash is public domain.
  #
  class Dictionary

    include Enumerable

    class << self

      #
      # Create a new Dictionary storing argument pairs as an initial mapping.
      #
      # TODO: Is this needed? Doesn't the super class do this?
      #
      # Returns Dictionary instance.
      #
      def [](*args)
        hsh = new
        if Hash === args[0]
          hsh.replace(args[0])
        elsif (args.size % 2) != 0
          raise ArgumentError, "odd number of elements for Hash"
        else
          while !args.empty?
            hsh[args.shift] = args.shift
          end
        end
        hsh
      end

      #
      # Like #new but the block sets the order instead of the default.
      #
      #   Dictionary.new_by{ |k,v| k }
      #
      def new_by(*args, &blk)
        new(*args).order_by(&blk)
      end

      #
      # Alternate to #new which creates a dictionary sorted by the key as a string.
      #
      #   d = Dictionary.alphabetic
      #   d["z"] = 1
      #   d["y"] = 2
      #   d["x"] = 3
      #   d  #=> {"x"=>3,"y"=>2,"z"=>2}
      #
      # This is equivalent to:
      #
      #   Dictionary.new.order_by { |key,value| key.to_s }
      #
      def alphabetic(*args, &block)
        new(*args, &block).order_by { |key,value| key.to_s }
      end

      # DEPRECATED: Use #alphabetic instead.
      alias :alpha :alphabetic

      #
      # Alternate to #new which auto-creates sub-dictionaries as needed.
      #
      # Examples
      #
      #   d = Dictionary.auto
      #   d["a"]["b"]["c"] = "abc"  #=> { "a"=>{"b"=>{"c"=>"abc"}}}
      #
      def auto(*args)
        #AutoDictionary.new(*args)
        leet = lambda { |hsh, key| hsh[key] = new(&leet) }
        new(*args, &leet)
      end
    end

    #
    # New Dictiionary.
    #
    def initialize(*args, &blk)
      @order = []
      @order_by = nil
      if blk
        dict = self                                  # This ensures automatic key entry effect the
        oblk = lambda{ |hsh, key| blk[dict,key] }    # dictionary rather then just the interal hash.
        @hash = Hash.new(*args, &oblk)
      else
        @hash = Hash.new(*args)
      end
    end

    #
    # Order of keys.
    #
    # Returns [Array].
    #
    def order
      reorder if @order_by
      @order
    end

    #
    # Keep dictionary sorted by a specific sort order.
    #
    # block - Ordering procedure.
    #
    # Returns +self+.
    #
    def order_by( &block )
      @order_by = block
      order
      self
    end

    #
    # Keep dictionary sorted by key.
    #
    #   d = Dictionary.new.order_by_key
    #   d["z"] = 1
    #   d["y"] = 2
    #   d["x"] = 3
    #   d  #=> {"x"=>3,"y"=>2,"z"=>2}
    #
    # This is equivalent to:
    #
    #   Dictionary.new.order_by { |key,value| key }
    #
    # The initializer Dictionary#alpha also provides this.
    #
    # Returns +self+.
    #
    def order_by_key
      if block_given?
        @order_by = Proc.new{ |k,v| yield(k) }
      else
        @order_by = Proc.new{ |k,v| k }
      end
      order
      self
    end

    #
    # Keep dictionary sorted by value.
    #
    #   d = Dictionary.new.order_by_value
    #   d["z"] = 1
    #   d["y"] = 2
    #   d["x"] = 3
    #   d  #=> {"x"=>3,"y"=>2,"z"=>2}
    #
    # This is equivalent to:
    #
    #   Dictionary.new.order_by { |key,value| value }
    #
    def order_by_value
      if block_given?
        @order_by = Proc.new{ |k,v| yield(v) }
      else
        @order_by = Proc.new{ |k,v| v }
      end
      order
      self
    end

    #
    # Re-apply the sorting procedure.
    #
    def reorder
      if @order_by
        assoc = @order.collect{ |k| [k,@hash[k]] }.sort_by(&@order_by)
        @order = assoc.collect{ |k,v| k }
      end
      @order
    end

    #def ==( hsh2 )
    #  return false if @order != hsh2.order
    #  super hsh2
    #end

    #
    # Is the dictionary instance equivalent to another?
    #
    def ==(hsh2)
      if hsh2.is_a?( Dictionary )
        @order == hsh2.order &&
        @hash  == hsh2.instance_variable_get("@hash")
      else
        false
      end
    end

    #
    # Lookup entry with key.
    #
    def [] key
      @hash[ key ]
    end

    #
    # Featch entry given +key+.
    #
    def fetch(key, *a, &b)
      @hash.fetch(key, *a, &b)
    end

    #
    # Store operator.
    #
    #   h[key] = value
    #
    # Or with additional index.
    #
    #  h[key,index] = value
    #
    def []=(k, i=nil, v=nil)
      if v
        insert(i,k,v)
      else
        store(k,i)
      end
    end

    #
    # Insert entry into dictionary at specific index position.
    #
    # index - [Integer] Position of order placement.
    # key   - [Object]  Key to associate with value.
    # value - [Object]  Value to associate with key.
    #
    # Returns `value` stored.
    #
    def insert(index, key, value)
      @order.insert(index, key)
      @hash.store(key, value)
    end

    #
    # Add entry into dictionary.
    #
    # Returns `value`.
    #
    def store(key, value)
      @order.push(key) unless @hash.has_key?(key)
      @hash.store(key, value)
    end

    #
    # Clear dictionary of all entries.
    #
    def clear
      @order = []
      @hash.clear
    end

    #
    # Delete the entry with given +key+.
    #
    def delete(key)
      @order.delete(key)
      @hash.delete(key)
    end

    #
    # Iterate over each key.
    #
    def each_key
      order.each { |k| yield( k ) }
      self
    end

    #
    # Iterate over each value.
    #
    def each_value
      order.each { |k| yield( @hash[k] ) }
      self
    end

    #
    # Iterate over each key-value pair.
    #
    def each
      order.each { |k| yield( k,@hash[k] ) }
      self
    end

    alias each_pair each

    #
    # Delete entry if it fits conditional block.
    #
    def delete_if
      order.clone.each { |k| delete k if yield(k,@hash[k]) }
      self
    end

    #
    # List of all dictionary values.
    #
    # Returns [Array].
    #
    def values
      ary = []
      order.each { |k| ary.push @hash[k] }
      ary
    end

    #
    # List of all dictionary keys.
    #
    # Returns [Array].
    #
    def keys
      order
    end

    #
    # Invert the dictionary.
    #
    # Returns [Dictionary] New dictionary that is inverse of the original.
    #
    def invert
      hsh2 = self.class.new
      order.each { |k| hsh2[@hash[k]] = k }
      hsh2
    end

    #
    # Reject entries based on give condition block and return
    # new dictionary.
    #
    # Returns [Dictionary].
    #
    def reject(&block)
      self.dup.delete_if(&block)
    end

    #
    # Reject entries based on give condition block.
    #
    # Returns [Hash] of rejected entries.
    #
    # FIXME: This looks like it is implemented wrong!!!
    #
    def reject!( &block )
      hsh2 = reject(&block)
      self == hsh2 ? nil : hsh2
    end

    #
    # Replace dictionary entries with new table.
    #
    def replace(hsh2)
      case hsh2
      when Dictionary
        @order = hsh2.order
        @hash  = hsh2.to_h
      when Hash
        @hash  = hsh2
        @order = @hash.keys
      else
        @hash  = hsh2.to_h
        @order = @hash.keys
      end
      reorder
    end

    #
    # Remove entry from the to top of dictionary.
    #
    def shift
      key = order.first
      key ? [key,delete(key)] : super
    end

    #
    # Push entry on to the top of dictionary.
    #
    def unshift( k,v )
      unless @hash.include?( k )
        @order.unshift( k )
        @hash.store( k,v )
        true
      else
        false
      end
    end

    #
    # Same as #push.
    #
    def <<(kv)
      push(*kv)
    end

    #
    # Push entry on to bottom of the dictionary.
    #
    def push(k,v)
      unless @hash.include?( k )
        @order.push( k )
        @hash.store( k,v )
        true
      else
        false
      end
    end

    #
    # Pop entry off the bottom of dictionary.
    #
    def pop
      key = order.last
      key ? [key,delete(key)] : nil
    end

    #
    # Inspection string for Dictionary.
    #
    # Returns [String].
    #
    def inspect
      ary = []
      each {|k,v| ary << k.inspect + "=>" + v.inspect}
      '{' + ary.join(", ") + '}'
    end

    #
    # Duplicate dictionary.
    #
    # Returns [Dictionary].
    #
    def dup
      a = []
      each{ |k,v| a << k; a << v }
      self.class[*a]
    end

    #
    # Update dictionary with other hash.
    #
    # Returns self.
    #
    def update( hsh2 )
      hsh2.each { |k,v| self[k] = v }
      reorder
      self
    end

    alias :merge! update

    #
    # Merge other hash creating new dictionary.
    #
    # Returns [Dictionary].
    #
    def merge(hsh2)
      self.dup.update(hsh2)
    end

    #
    # Select items from dictiornary.
    #
    # Returns [Array] of two-element arrays.
    #
    def select
      ary = []
      each { |k,v| ary << [k,v] if yield k,v }
      ary
    end

    #
    # Reverse the order of the dictionary.
    #
    # Returns self.
    #
    def reverse!
      @order.reverse!
      self
    end

    #
    # Reverse the order of duplicte dictionary.
    #
    # Returns [Dictionary].
    #
    def reverse
      dup.reverse!
    end

    #
    # Get/set initial entry value.
    #
    def first(x=nil)
      return @hash[order.first] unless x
      order.first(x).collect { |k| @hash[k] }
    end

    #
    # Get/set last entry value.
    #
    def last(x=nil)
      return @hash[order.last] unless x
      order.last(x).collect { |k| @hash[k] }
    end

    #
    # Number of items in the dictionary.
    #
    def length
      @order.length
    end

    alias :size :length

    #
    # Is the dictionary empty?
    #
    # Returns `true` or `false`.
    #
    def empty?
      @hash.empty?
    end

    #
    # Does the dictionary have a given +key+.
    #
    # Returns `true` or `false`.
    #
    def has_key?(key)
      @hash.has_key?(key)
    end

    #
    # Does the dictionary have a given +key+.
    #
    # Returns `true` or `false`.
    #
    def key?(key)
      @hash.key?(key)
    end

    #
    # Convert to array.
    #
    # Returns [Array] of two-element arrays.
    #
    def to_a
      ary = []
      each { |k,v| ary << [k,v] }
      ary
    end

    #
    # Convert to array then to string.
    #
    # Returns [String].
    #
    def to_s
      self.to_a.to_s
    end

    #
    # Get a duplicate of the underlying hash table.
    #
    # Returns [Hash].
    #
    def to_hash
      @hash.dup
    end

    #
    # Get a duplicate of the underlying hash table.
    #
    # Returns [Hash].
    #
    def to_h
      @hash.dup
    end

  protected

    #
    # Underlying hash table.
    #
    def hash_table
      @hash
    end

  end

end
