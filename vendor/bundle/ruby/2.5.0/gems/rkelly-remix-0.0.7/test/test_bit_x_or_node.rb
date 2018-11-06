require File.dirname(__FILE__) + "/helper"

class BitXOrNodeTest < NodeTestCase
  def test_to_sexp
    node = BitXOrNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:bit_xor, [:lit, 5], [:lit, 10]], node)
  end
end
