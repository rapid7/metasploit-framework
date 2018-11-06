unless ([1].rindex{true} rescue false)
  class Array
    require 'backports/tools/alias_method_chain'
    require 'enumerator'

    def rindex_with_block(*arg)
      return to_enum(:rindex) if !block_given? && arg.empty?
      return rindex_without_block(*arg) unless block_given? && arg.empty?
      i = 0
      reverse_each{|o| i += 1; return size - i if yield o}
      return nil
    end
    Backports.alias_method_chain self, :rindex, :block
  end
end
