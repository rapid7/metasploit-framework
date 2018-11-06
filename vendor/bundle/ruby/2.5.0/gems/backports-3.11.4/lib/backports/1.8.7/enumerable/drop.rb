unless Enumerable.method_defined? :drop
  require 'backports/tools/arguments'

  module Enumerable
    def drop(n)
      n = Backports.coerce_to_int(n)
      raise ArgumentError, "attempt to drop negative size" if n < 0
      ary = to_a
      return [] if n > ary.size
      ary[n...ary.size]
    end
  end
end
