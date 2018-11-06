require File.dirname(__FILE__) + "/helper"

class BitwiseNotNodeTest < NodeTestCase
  def test_failure
    node = BitwiseNotNode.new(NumberNode.new(10))
    assert_sexp([:bitwise_not, [:lit, 10]], node)
  end
end
