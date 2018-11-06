unless ("abc".upto("def", true){} rescue false)
  require 'backports/tools/alias_method_chain'
  require 'enumerator'

  class String
    def upto_with_exclusive(to, excl=false)
      return upto_without_exclusive(to){|s| yield s} if block_given? && !excl
      r = Range.new(self, to, excl)
      return r.to_enum unless block_given?
      r.each{|s| yield s}
      self
    end
    Backports.alias_method_chain self, :upto, :exclusive
  end
end
