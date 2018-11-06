require File.dirname(__FILE__) + "/helper"

class NotEqualNodeTest < NodeTestCase
  def test_to_sexp
    node = NotEqualNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:not_equal, [:lit, 5], [:lit, 10]], node)
  end
end
