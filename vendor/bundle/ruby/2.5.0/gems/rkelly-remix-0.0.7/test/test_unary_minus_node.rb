require File.dirname(__FILE__) + "/helper"

class UnaryMinusNodeTest < NodeTestCase
  def test_to_sexp
    node = UnaryMinusNode.new(NumberNode.new(10))
    assert_sexp([:u_minus, [:lit, 10]], node)
  end
end
