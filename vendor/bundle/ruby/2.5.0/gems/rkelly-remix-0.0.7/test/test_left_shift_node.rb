require File.dirname(__FILE__) + "/helper"

class LeftShiftNodeTest < NodeTestCase
  def test_to_sexp
    node = LeftShiftNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:lshift, [:lit, 5], [:lit, 10]], node)
  end
end
