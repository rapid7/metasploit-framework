module Backports
  # Helper method to coerce a value into a specific class.
  # Raises a TypeError if the coercion fails or the returned value
  # is not of the right class.
  # (from Rubinius)
  def self.coerce_to(obj, cls, meth)
    return obj if obj.kind_of?(cls)

    begin
      ret = obj.__send__(meth)
    rescue Exception => e
      raise TypeError, "Coercion error: #{obj.inspect}.#{meth} => #{cls} failed:\n" \
                       "(#{e.message})"
    end
    raise TypeError, "Coercion error: obj.#{meth} did NOT return a #{cls} (was #{ret.class})" unless ret.kind_of? cls
    ret
  end

  def self.coerce_to_int(obj)
    coerce_to(obj, Integer, :to_int)
  end

  def self.coerce_to_ary(obj)
    coerce_to(obj, Array, :to_ary)
  end

  def self.coerce_to_str(obj)
    coerce_to(obj, String, :to_str)
  end

  def self.coerce_to_hash(obj)
    coerce_to(obj, Hash, :to_hash)
  end

  def self.coerce_to_options(obj, *options)
    hash = coerce_to_hash(obj)
    hash.values_at(*options)
  end

  def self.coerce_to_option(obj, option)
    coerce_to_options(obj, option)[0]
  end

  def self.is_array?(obj)
    coerce_to(obj, Array, :to_ary) if obj.respond_to? :to_ary
  end

  def self.try_convert(obj, cls, meth)
    return obj if obj.kind_of?(cls)
    return nil unless obj.respond_to?(meth)
    ret = obj.__send__(meth)
    raise TypeError, "Coercion error: obj.#{meth} did NOT return a #{cls} (was #{ret.class})" unless ret.nil? || ret.kind_of?(cls)
    ret
  end

  # Checks for a failed comparison (in which case it throws an ArgumentError)
  # Additionally, it maps any negative value to -1 and any positive value to +1
  # (from Rubinius)
  def self.coerce_to_comparison(a, b, cmp = (a <=> b))
    raise ArgumentError, "comparison of #{a} with #{b} failed" if cmp.nil?
    return 1 if cmp > 0
    return -1 if cmp < 0
    0
  end

  # Used internally to make it easy to deal with optional arguments
  # (from Rubinius)
  Undefined = Object.new
end
