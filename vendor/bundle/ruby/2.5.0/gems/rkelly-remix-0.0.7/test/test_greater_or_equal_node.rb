require File.dirname(__FILE__) + "/helper"

class GreaterOrEqualNodeTest < NodeTestCase
  def test_to_sexp
    node = GreaterOrEqualNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:greater_or_equal, [:lit, 5], [:lit, 10]], node)
  end
end
