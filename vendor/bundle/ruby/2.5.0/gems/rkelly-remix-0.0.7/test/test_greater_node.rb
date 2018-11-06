require File.dirname(__FILE__) + "/helper"

class GreaterNodeTest < NodeTestCase
  def test_to_sexp
    node = GreaterNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:greater, [:lit, 5], [:lit, 10]], node)
  end
end
