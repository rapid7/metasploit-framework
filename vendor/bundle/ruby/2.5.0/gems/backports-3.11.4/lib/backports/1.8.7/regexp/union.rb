unless (Regexp.union(%w(a b)) rescue false)
  require 'backports/tools/alias_method_chain'

  class << Regexp
    def union_with_array_argument(*arg)
      return union_without_array_argument(*arg) unless arg.size == 1
      union_without_array_argument(*arg.first)
    end
    Backports.alias_method_chain self, :union, :array_argument
  end
end
