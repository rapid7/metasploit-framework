require File.dirname(__FILE__) + "/helper"

class WhileNodeTest < NodeTestCase
  def test_to_sexp
    initializer = AssignExprNode.new(NumberNode.new(10))
    decl = VarDeclNode.new('foo', initializer)
    stmt = VarStatementNode.new([decl])
    node = WhileNode.new(TrueNode.new('true'), stmt)

    assert_sexp([:while,
                [:true],
                [:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]],
    ], node)
  end
end
