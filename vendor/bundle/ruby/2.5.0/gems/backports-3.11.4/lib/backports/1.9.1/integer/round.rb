if Integer.instance_method(:round).arity.zero?
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  class Integer
    def round_with_digits(ndigits=0)
      ndigits = Backports::coerce_to_int(ndigits)
      case
      when ndigits.zero?
        self
      when ndigits > 0
        raise RangeError if ndigits >= 1<<31
        Float(self)
      else
        pow = 10 ** (-ndigits)
        return 0 if pow.is_a?(Float) # when ndigits hugely negative
        remain = self % pow
        comp = self < 0 ? :<= : :<
        remain -= pow unless remain.send(comp, pow / 2)
        self - remain
      end
    end
    Backports.alias_method_chain self, :round, :digits
  end
end
