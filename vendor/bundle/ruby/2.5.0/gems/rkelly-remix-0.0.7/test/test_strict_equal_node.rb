require File.dirname(__FILE__) + "/helper"

class StrictEqualNodeTest < NodeTestCase
  def test_to_sexp
    node = StrictEqualNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:strict_equal, [:lit, 5], [:lit, 10]], node)
  end
end
