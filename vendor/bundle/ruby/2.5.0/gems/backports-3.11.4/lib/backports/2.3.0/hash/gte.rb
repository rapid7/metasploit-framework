unless Hash.method_defined? :>=
  require 'backports/tools/arguments'
  require 'backports/2.3.0/hash/lte'
  class Hash
    def >=(hash)
      hash = Backports.coerce_to_hash(hash)
      hash <= self
    end
  end
end
