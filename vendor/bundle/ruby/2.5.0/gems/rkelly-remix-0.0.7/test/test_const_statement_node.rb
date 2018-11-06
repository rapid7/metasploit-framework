require File.dirname(__FILE__) + "/helper"

class ConstStatementNodeTest < NodeTestCase
  def test_to_sexp
    initializer = AssignExprNode.new(NumberNode.new(10))
    decl = VarDeclNode.new('foo', initializer, true)
    stmt = ConstStatementNode.new([decl])

    assert_sexp(
      [:const, [[:const_decl, :foo, [:assign, [:lit, 10]]]]],
      stmt
    )
  end
end
