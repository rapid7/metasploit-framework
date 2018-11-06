unless Array.method_defined? :sample
  require 'backports/tools/arguments'

  class Array
    def sample(n = Backports::Undefined, options = Backports::Undefined)
      if options == Backports::Undefined && n.respond_to?(:to_hash)
        n, options = options, n
      end
      rng = Backports.coerce_to_option(options, :random) unless options == Backports::Undefined
      generator = if rng.respond_to? :rand
        Proc.new do |nb|
          r = Backports::coerce_to_int(rng.rand(nb))
          raise RangeError, "random generator returned #{r} which is not in 0...#{nb}" if r < 0 || r >= nb
          r
        end
      else
        Kernel.method(:rand)
      end
      return self[generator.call(size)] if n == Backports::Undefined
      n = Backports.coerce_to_int(n)
      raise ArgumentError, "negative array size" if n < 0
      n = size if n > size
      result = Array.new(self)
      n.times do |i|
        r = i + generator.call(size - i)
        result[i], result[r] = result[r], result[i]
      end
      result[n..size] = []
      result
    end
  end
end
