unless Comparable.method_defined? :clamp
  require 'backports/tools/arguments'

  module Comparable
    def clamp(min, max)
      if Backports.coerce_to_comparison(min, max) > 0
        raise ArgumentError, "min argument must be smaller than max argument"
      end
      case Backports.coerce_to_comparison(self, min)
      when 0
        self
      when -1
        min
      else
        self > max ? max : self
      end
    end
  end
end
