require File.dirname(__FILE__) + "/helper"

class UnaryPlusNodeTest < NodeTestCase
  def test_to_sexp
    node = UnaryPlusNode.new(NumberNode.new(10))
    assert_sexp([:u_plus, [:lit, 10]], node)
  end
end
