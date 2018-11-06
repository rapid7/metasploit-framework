unless Integer.method_defined?(:bit_length) || Fixnum.method_defined?(:bit_length)
  require 'backports/2.0.0/range/bsearch'
  class Fixnum
    def bit_length
      n = if self >= 0
        self + 1
      else
        -self
      end
      (0...8 * size).bsearch{|i| n <= (1 << i) }
    end
  end
end
