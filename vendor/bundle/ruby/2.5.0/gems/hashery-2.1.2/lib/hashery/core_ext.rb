class Hash

  #
  # Create a hash given an `initial_hash`.
  #
  # initial_hash - Hash or hash-like object to use as priming data.
  # block        - Procedure used by initialize (e.g. default_proc).
  #
  # Returns a `Hash`.
  #
  def self.create(initial_hash={}, &block)
    o = new &block
    o.update(initial_hash)
    o
  end

  #
  # Like #fetch but returns the results of calling `default_proc`, if defined,
  # otherwise `default`.
  #
  # key - Hash key to lookup.
  #
  # Returns value of Hash entry or `nil`.
  #
  def retrieve(key)
    fetch(key, default_proc ? default_proc[self, key] : default)
  end

  #
  # Convert to Hash.
  #
  def to_hash
    dup  # -or- `h = {}; each{ |k,v| h[k] = v }; h` ?
  end \
  unless method_defined?(:to_hash)

  #
  # For a Hash, `#to_h` is the same as `#to_hash`.
  #
  alias :to_h :to_hash \
  unless method_defined?(:to_h)

  #
  # Synonym for Hash#rekey, but modifies the receiver in place (and returns it).
  #
  # key_map - Hash of old key to new key.
  # block   - Procedure to convert keys, which can take just the key
  #           or both key and value as arguments.
  #
  # Examples
  #
  #   foo = { :name=>'Gavin', :wife=>:Lisa }
  #   foo.rekey!{ |k| k.to_s }  #=>  { "name"=>"Gavin", "wife"=>:Lisa }
  #   foo.inspect               #=>  { "name"=>"Gavin", "wife"=>:Lisa }
  #
  # Returns `Hash`.
  #
  def rekey(key_map=nil, &block)
    if !(key_map or block)
      block = lambda{|k| k.to_sym}
    end

    key_map ||= {} 

    hash = {}

    (keys - key_map.keys).each do |key|
      hash[key] = self[key]
    end

    key_map.each do |from, to|
      hash[to] = self[from] if key?(from)
    end

    hash2 = {}

    if block
      case block.arity
      when 0
        raise ArgumentError, "arity of 0 for #{block.inspect}"
      when 2
        hash.each do |k,v|
          nk = block.call(k,v)
          hash2[nk] = v
        end
      else
        hash.each do |k,v|
          nk = block[k]
          hash2[nk] = v
        end
      end
    else
      hash2 = hash
    end

    hash2
  end

  #
  # Synonym for Hash#rekey, but modifies the receiver in place (and returns it).
  #
  # key_map - Hash of old key to new key.
  # block   - Procedure to convert keys, which can take just the key
  #           or both key and value as arguments.
  #
  # Examples
  #
  #   foo = { :name=>'Gavin', :wife=>:Lisa }
  #   foo.rekey!{ |k| k.to_s }  #=>  { "name"=>"Gavin", "wife"=>:Lisa }
  #   foo                       #=>  { "name"=>"Gavin", "wife"=>:Lisa }
  #
  # Returns `Hash`.
  #
  def rekey!(key_map=nil, &block)
    replace(rekey(key_map, &block))
  end

end

