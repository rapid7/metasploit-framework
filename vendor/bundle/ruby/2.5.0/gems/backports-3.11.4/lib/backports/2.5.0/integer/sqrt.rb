class Integer
  require 'backports/tools/arguments'
  require 'backports/2.1.0/bignum/bit_length'
  require 'backports/2.1.0/fixnum/bit_length'

  def self.sqrt(n)
    n = Backports.coerce_to_int(n)
    return Math.sqrt(n).to_i if n <= 9_999_899_999_899_999_322_536_673_279
    bits_shift = n.bit_length/2 + 1
    bitn_mask = root = 1 << bits_shift
    while true
      root ^= bitn_mask if (root * root) > n
      bitn_mask >>= 1
      return root if bitn_mask == 0
      root |= bitn_mask
    end
  end
end unless Integer.respond_to? :sqrt
