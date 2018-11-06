if Numeric.instance_method(:round).arity.zero?
  require 'backports/tools/arguments'
  require 'backports/tools/alias_method_chain'

  class Numeric
    def round_with_digits(ndigits=0)
      ndigits = Backports::coerce_to_int(ndigits)
      ndigits.zero? ? round_without_digits : Float(self).round(ndigits)
    end
    Backports.alias_method_chain self, :round, :digits
  end
end
