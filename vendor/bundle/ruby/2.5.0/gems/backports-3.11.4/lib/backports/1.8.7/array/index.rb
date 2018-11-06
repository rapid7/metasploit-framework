unless ([1].index{true} rescue false)
  require 'backports/tools/alias_method_chain'
  require 'enumerator'

  class Array
    def index_with_block(*arg)
      return to_enum(:index_with_block) if arg.empty? && !block_given?
      return index_without_block(*arg) unless block_given? && arg.empty?
      each_with_index{|o,i| return i if yield o}
      return nil
    end
    Backports.alias_method_chain self, :index, :block
    alias_method :find_index, :index
  end
end
