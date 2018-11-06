require File.dirname(__FILE__) + "/helper"

class RightShiftNodeTest < NodeTestCase
  def test_to_sexp
    node = RightShiftNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:rshift, [:lit, 5], [:lit, 10]], node)
  end
end
