unless Enumerable.method_defined? :cycle
  require 'backports/tools/arguments'
  require 'enumerator'

  module Enumerable
    def cycle(n = nil)
      return to_enum(:cycle, n) unless block_given?
      n = n && Backports.coerce_to_int(n)
      if n == nil || n >= 1
        cache = []
        each do |elem|
          cache << elem
          yield elem
        end
        if n
          (n-1).times { cache.each{|e| yield e } }
        else
          loop        { cache.each{|e| yield e } }
        end unless cache.empty?
      end
      nil
    end
  end
end
