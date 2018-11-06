if Float.instance_method(:round).arity.zero?
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  class Float
    def round_with_digits(ndigits=0)
      ndigits = Backports::coerce_to_int(ndigits)
      case
      when ndigits == 0
        round_without_digits
      when ndigits < 0
        p = 10 ** -ndigits
        p > abs ? 0 : (self / p).round * p
      else
        p = 10 ** ndigits
        prod = self * p
        prod.infinite? || prod.nan? ? self : prod.round.to_f / p
      end
    end
    Backports.alias_method_chain self, :round, :digits
  end
end
