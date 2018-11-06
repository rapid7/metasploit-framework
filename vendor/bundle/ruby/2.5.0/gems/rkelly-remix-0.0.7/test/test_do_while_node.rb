require File.dirname(__FILE__) + "/helper"

class DoWhileNodeTest < NodeTestCase
  def test_to_sepx
    initializer = AssignExprNode.new(NumberNode.new(10))
    decl = VarDeclNode.new('foo', initializer)
    stmt = VarStatementNode.new([decl])
    node = DoWhileNode.new(stmt, TrueNode.new('true'))

    assert_sexp([:do_while, [:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]],
                [:true]], node)
  end
end
