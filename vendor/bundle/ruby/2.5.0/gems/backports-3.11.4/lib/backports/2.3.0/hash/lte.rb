unless Hash.method_defined? :<=
  require 'backports/tools/arguments'
  class Hash
    def <=(hash)
      hash = Backports.coerce_to_hash(hash)
      return false unless size <= hash.size
      each do |k, v|
        v2 = hash.fetch(k){ return false }
        return false unless v2 == v
      end
      true
    end
  end
end
