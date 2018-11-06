require File.dirname(__FILE__) + "/helper"

class AssignExprNodeTest < NodeTestCase
  def test_to_sexp
    node = AssignExprNode.new(NumberNode.new(10))
    assert_sexp [:assign, [:lit, 10]], node
  end
end
