require File.dirname(__FILE__) + "/helper"

class UnsignedRightShiftNodeTest < NodeTestCase
  def test_to_sexp
    node = UnsignedRightShiftNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:urshift, [:lit, 5], [:lit, 10]], node)
  end
end
