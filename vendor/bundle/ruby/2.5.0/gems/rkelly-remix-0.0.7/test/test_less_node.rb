require File.dirname(__FILE__) + "/helper"

class LessNodeTest < NodeTestCase
  def test_to_sexp
    node = LessNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:less, [:lit, 5], [:lit, 10]], node)
  end
end
