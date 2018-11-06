require './test/test_helper'

class BitLengthTest < Test::Unit::TestCase
  def test_big_num # Issue #95
    require 'backports/2.1.0/bignum/bit_length'
    r = 91178362617816881166579720176198217549251305244541026425489888079462471837807
    assert_equal 256, r.bit_length
    r = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    assert_equal 256, r.bit_length
  end
end
