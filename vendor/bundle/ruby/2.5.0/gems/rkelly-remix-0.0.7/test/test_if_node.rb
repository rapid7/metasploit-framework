require File.dirname(__FILE__) + "/helper"

class IfNodeTest < NodeTestCase
  def test_to_sexp
    initializer = AssignExprNode.new(NumberNode.new(20))
    decl = VarDeclNode.new('foo', initializer)
    stmt = VarStatementNode.new([decl])
    and_node = LogicalAndNode.new(NumberNode.new(5), NumberNode.new(10))
    node = IfNode.new(and_node, stmt)

    assert_sexp([:if,
                [:and, [:lit, 5], [:lit, 10]],
                [:var, [[:var_decl, :foo, [:assign, [:lit, 20]]]]]],
                node)
                
  end
end
