require File.dirname(__FILE__) + "/helper"

class MultiplyNodeTest < NodeTestCase
  def test_to_sexp
    node = MultiplyNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:multiply, [:lit, 5], [:lit, 10]], node)
  end
end
