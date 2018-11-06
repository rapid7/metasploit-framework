unless Array.method_defined? :rotate
  class Array
    def rotate(n=1)
      Array.new(self).rotate!(n)
    end
  end
end

unless Array.method_defined? :rotate!
  require 'backports/tools/arguments'
  class Array
    def rotate!(n=1)
      n = Backports.coerce_to_int(n) % (empty? ? 1 : size)
      concat(slice!(0, n))
    end
  end
end
