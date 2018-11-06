module Hashery

  # A PathHash is a hash whose values can be accessed in the normal manner,
  # or with keys that are slash (`/`) separated strings. To get the whole hash
  # as a single flattened level, call `#flat`. All keys are converted to strings.
  # All end-of-the-chain values are kept in whatever value they are.
  #
  #   s = PathHash['a' => 'b', 'c' => {'d' => :e}]
  #   s['a'] #=> 'b'
  #   s['c'] #=> {slashed: 'd'=>:e}
  #   s['c']['d'] #=> :e
  #   s['c/d'] #=> :e
  #
  # PathHash is derived from the SlashedHash class in the HashMagic project
  # by Daniel Parker <gems@behindlogic.com>.
  #   
  # Copyright (c) 2006 BehindLogic (http://hash_magic.rubyforge.org)
  #
  # Authors: Daniel Parker
  #
  # TODO: This class is very much a work in progess and will be substantially rewritten
  # for future versions.
  #
  class PathHash < Hash

    #
    # Initialize PathHash.
    #
    # hsh - Priming Hash.
    #
    def initialize(hsh={})
      raise ArgumentError, "must be a hash or array of slashed values" unless hsh.is_a?(Hash) || hsh.is_a?(Array)
      @constructor = hsh.is_a?(Hash) ? hsh.class : Hash
      @flat = flatten_to_hash(hsh)
    end

    # Standard Hash methods, plus the overwritten ones
    #include StandardHashMethodsInRuby

    # Behaves like the usual Hash#[] method, but you can access nested hash
    # values by composing a single key of the traversing keys joined by '/':
    #
    #   hash['c']['d'] # is the same as:
    #   hash['c/d']
    #
    def [](key)
      rg = Regexp.new("^#{key}/?")
      start_obj = if @constructor == OrderedHash
        @constructor.new((@flat.instance_variable_get(:@keys_in_order) || []).collect {|e| e.gsub(rg,'')})
      else
        @constructor.new
      end
      v = @flat.has_key?(key) ? @flat[key] : self.class.new(@flat.reject {|k,v| !(k == key || k =~ rg)}.inject(start_obj) {|h,(k,v)| h[k.gsub(rg,'')] = v; h})
      v.is_a?(self.class) && v.empty? ? nil : v
    end

    #
    # Same as above, except sets value rather than retrieving it.
    #
    def []=(key,value)
      @flat.reject! {|k,v| k == key || k =~ Regexp.new("^#{key}/")}
      if value.is_a?(Hash)
        flatten_to_hash(value).each do |hk,hv|
          @flat[key.to_s+'/'+hk.to_s] = hv
        end
      else
        @flat[key.to_s] = value
      end
    end

    def clear # :nodoc:
      @flat.clear
    end

    #
    #
    #
    def fetch(key,default=:ehisehoah0928309q98y30,&block) # :nodoc:
      value = @flat.has_key?(key) ? @flat[key] : self.class.new(@flat.reject {|k,v| !(k == key || k =~ Regexp.new("^#{key}/"))}.inject({}) {|h,(k,v)| h[k.split('/',2)[1]] = v; h})
      if value.is_a?(self.class) && value.empty?
        if default == :ehisehoah0928309q98y30
          if block_given?
            block.call(key)
          else
            raise IndexError
          end
          value
        else
          default
        end
      else
        value
      end
    end

    #
    # Delete entry from Hash. Slashed keys can be used here, too.
    #
    # key   - The key to delete.
    # block - Produces the return value if key not found.
    #
    # Returns delete value.
    #
    def delete(key,&block)
      value = @flat.has_key?(key) ? @flat[key] : self.class.new(@flat.reject {|k,v| !(k == key || k =~ Regexp.new("^#{key}/"))}.inject({}) {|h,(k,v)| h[k.split('/',2)[1]] = v; h})
      return block.call(key) if value.is_a?(self.class) && value.empty? && block_given?
      @flat.keys.reject {|k| !(k == key || k =~ Regexp.new("^#{key}/"))}.each {|k| @flat.delete(k)}
      return value
    end

    #
    def empty?
      @flat.empty?
    end

    # This gives you the slashed key of the value, no matter where the value is in the tree.
    def index(value)
      @flat.index(value)
    end

    #
    def inspect
      @flat.inspect.insert(1,'slashed: ')
    end

    # This gives you only the top-level keys, no slashes. To get the list of slashed keys, do hash.flat.keys
    def keys
      @flat.inject([]) {|a,(k,v)| a << [k.split('/',2)].flatten[0]; a}.uniq
    end

    # This is rewritten to mean something slightly different than usual: Use this to restructure the hash, for cases when you
    # end up with an array holding several hashes.
    def rehash # :nodoc:
      @flat.rehash
    end

    # Gives a list of all keys in all levels in the multi-level hash, joined by slashes.
    #
    #   {'a'=>{'b'=>'c', 'c'=>'d'}, 'b'=>'c'}.slashed.flat.keys
    #   #=> ['a/b', 'a/c', 'b']
    #
    def flat
      @flat
    end

    # Expands the whole hash to Hash objects ... not useful very often, it seems.
    def expand
      inject({}) {|h,(k,v)| h[k] = v.is_a?(SlashedHash) ? v.expand : v; h}
    end

    def to_string_array
      flatten_to_array(flat,[])
    end

    def slashed # :nodoc:
      self
    end

    # Same as ordered! but returns a new SlashedHash object instead of modifying the same.
    def ordered(*keys_in_order)
      dup.ordered!(*keys_in_order)
    end

    # Sets the SlashedArray as ordered. The *keys_in_order must be a flat array
    # of slashed keys that specify the order for each level:
    #
    #   s = {'a'=>{'b'=>'c', 'c'=>'d'}, 'b'=>'c'}.slashed
    #   s.ordered!('b', 'a/c', 'a/b')
    #   s.expand # => {'b'=>'c', 'a'=>{'c'=>'d', 'b'=>'c'}}
    #   # Note that the expanded hashes will *still* be ordered!
    #
    def ordered!(*keys_in_order)
      return self if @constructor == OrderedHash
      @constructor = OrderedHash
      @flat = @flat.ordered(*keys_in_order)
      self
    end

    #
    def ==(other)
      case other
      when SlashedHash
        @slashed == other.instance_variable_get(:@slashed)
      when Hash
        self == SlashedHash.new(other)
      else
        raise TypeError, "Cannot compare #{other.class.name} with SlashedHash"
      end
    end

    private

      def flatten_to_hash(hsh)
        flat = @constructor.new
        if hsh.is_a?(Array)
          hsh.each do |e|
            flat.merge!(flatten_to_hash(e))
          end
        elsif hsh.is_a?(Hash)
          hsh.each do |k,v|
            if v.is_a?(Hash)
              flatten_to_hash(v).each do |hk,hv|
                flat[k.to_s+'/'+hk.to_s] = hv
              end
            else
              flat[k.to_s] = v
            end
          end
        else
          ks = hsh.split('/',-1)
          v = ks.pop
          ks = ks.join('/')
          if !flat[ks].nil?
            if flat[ks].is_a?(Array)
              flat[ks] << v
            else
              flat[ks] = [flat[ks], v]
            end
          else
            flat[ks] = v
          end
        end
        flat
      end

      def flatten_to_array(value,a)
        if value.is_a?(Array)
          value.each {|e| flatten_to_array(e,a)}
        elsif value.is_a?(Hash)
          value.inject([]) {|aa,(k,v)| flatten_to_array(v,[]).each {|vv| aa << k+'/'+vv.to_s}; aa}.each {|e| a << e}
        else
          a << value.to_s
        end
        a
      end
  end

end
