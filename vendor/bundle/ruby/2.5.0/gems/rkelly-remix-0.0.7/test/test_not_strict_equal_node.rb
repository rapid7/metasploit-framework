require File.dirname(__FILE__) + "/helper"

class NotStrictEqualNodeTest < NodeTestCase
  def test_to_sexp
    node = NotStrictEqualNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:not_strict_equal, [:lit, 5], [:lit, 10]], node)
  end
end
