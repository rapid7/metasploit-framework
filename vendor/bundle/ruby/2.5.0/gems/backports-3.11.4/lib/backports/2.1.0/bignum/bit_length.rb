unless Integer.method_defined?(:bit_length) || Bignum.method_defined?(:bit_length)
  require 'backports/2.0.0/range/bsearch'
  class Bignum
    def bit_length
      # We use the fact that bignums use the minimum number of "words" necessary
      # where "words" is some number of bytes <= to the size of a fixnum
      # So we have (size - word_size) * 8 < bit_length <= size * 8
      n = 8 * (size - 42.size)
      smaller = self >> n
      if smaller >= 0
        smaller += 1
      else
        smaller = -smaller
      end
      n + (1..8 * 42.size).bsearch{|i| smaller <= (1 << i) }
    end
  end
end
