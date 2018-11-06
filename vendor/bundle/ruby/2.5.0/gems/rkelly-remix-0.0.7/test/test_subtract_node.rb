require File.dirname(__FILE__) + "/helper"

class SubtractNodeTest < NodeTestCase
  def test_subtract
    node = SubtractNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:subtract, [:lit, 5], [:lit, 10]], node)
  end
end
