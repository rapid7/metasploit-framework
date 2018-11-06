require File.dirname(__FILE__) + "/helper"

class LessOrEqualNodeTest < NodeTestCase
  def test_to_sexp
    node = LessOrEqualNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:less_or_equal, [:lit, 5], [:lit, 10]], node)
  end
end
