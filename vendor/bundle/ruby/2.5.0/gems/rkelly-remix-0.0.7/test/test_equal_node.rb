require File.dirname(__FILE__) + "/helper"

class EqualNodeTest < NodeTestCase
  def test_to_sexp
    node = EqualNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:equal, [:lit, 5], [:lit, 10]], node)
  end
end
