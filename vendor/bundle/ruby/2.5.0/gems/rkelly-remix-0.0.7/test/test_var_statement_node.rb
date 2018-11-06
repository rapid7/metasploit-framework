require File.dirname(__FILE__) + "/helper"

class VarStatementNodeTest < NodeTestCase
  def test_to_sexp
    initializer = AssignExprNode.new(NumberNode.new(10))
    decl = VarDeclNode.new('foo', initializer)
    stmt = VarStatementNode.new([decl])

    assert_sexp(
      [:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]],
      stmt
    )
  end
end
