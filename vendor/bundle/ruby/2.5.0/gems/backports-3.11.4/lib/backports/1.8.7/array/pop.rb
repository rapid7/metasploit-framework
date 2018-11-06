unless ([1].pop(1) rescue false)
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  class Array
    def pop_with_optional_argument(n = Backports::Undefined)
      return pop_without_optional_argument if n == Backports::Undefined
      n = Backports.coerce_to_int(n)
      raise ArgumentError, "negative array size" if n < 0
      first = size - n
      first = 0 if first < 0
      slice!(first..size).to_a
    end
    Backports.alias_method_chain self, :pop, :optional_argument
  end
end
