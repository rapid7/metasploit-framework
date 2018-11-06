unless ([1].shift(1) rescue false)
  class Array
    require 'backports/tools/alias_method_chain'
    require 'backports/tools/arguments'

    def shift_with_optional_argument(n = Backports::Undefined)
      return shift_without_optional_argument if n == Backports::Undefined
      n = Backports.coerce_to_int(n)
      raise ArgumentError, "negative array size" if n < 0
      slice!(0, n)
    end
    Backports.alias_method_chain self, :shift, :optional_argument
  end
end
