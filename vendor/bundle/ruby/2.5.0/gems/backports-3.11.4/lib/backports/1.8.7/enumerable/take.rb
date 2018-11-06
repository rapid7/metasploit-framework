unless Enumerable.method_defined? :take
  require 'backports/1.8.7/enumerable/first'

  module Enumerable
    def take(n)
      first(n)
    end
  end
end
