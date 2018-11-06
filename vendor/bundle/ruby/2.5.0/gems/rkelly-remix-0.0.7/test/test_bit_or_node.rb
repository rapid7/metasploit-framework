require File.dirname(__FILE__) + "/helper"

class BitOrNodeTest < NodeTestCase
  def test_to_sexp
    node = BitOrNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:bit_or, [:lit, 5], [:lit, 10]], node)
  end
end
