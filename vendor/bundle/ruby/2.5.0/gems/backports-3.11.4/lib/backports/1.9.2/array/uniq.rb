unless [1,2].uniq{}.size == 1
  require 'backports/tools/alias_method_chain'

  class Array
    def uniq_with_block
      return uniq_without_block unless block_given?
      h = {}
      each do |elem|
        key = yield(elem)
        h[key] = elem unless h.has_key?(key)
      end
      h.values
    end
    Backports.alias_method_chain self, :uniq, :block
  end
end

unless [1,2].uniq!{}
  require 'backports/tools/alias_method_chain'

  class Array
    def uniq_with_block!
      replace self if frozen? # force error
      return uniq_without_block! unless block_given?
      u = uniq{|e| yield e}
      replace u unless u.size == size
    end
    Backports.alias_method_chain self, :uniq!, :block
  end
end
