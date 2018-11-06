require File.dirname(__FILE__) + "/helper"

class BitAndNodeTest < NodeTestCase
  def test_to_sexp
    node = BitAndNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:bit_and, [:lit, 5], [:lit, 10]], node)
  end
end
