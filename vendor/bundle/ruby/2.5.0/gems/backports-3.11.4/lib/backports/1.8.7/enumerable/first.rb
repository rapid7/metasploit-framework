unless Enumerable.method_defined? :first
  require 'backports/tools/arguments'

  module Enumerable
    def first(n = Backports::Undefined)
      if n == Backports::Undefined
        each{|obj| return obj}
        nil
      else
        n = Backports.coerce_to_int(n)
        raise ArgumentError, "attempt to take negative size: #{n}" if n < 0
        array = []
        each do |elem|
          array << elem
          break if array.size >= n
        end unless n == 0
        array
      end
    end
  end
end
