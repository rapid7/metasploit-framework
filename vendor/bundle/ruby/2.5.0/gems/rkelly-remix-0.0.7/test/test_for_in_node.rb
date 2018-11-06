require File.dirname(__FILE__) + "/helper"

class ForInNodeTest < NodeTestCase
  def test_to_sexp
    initializer = AssignExprNode.new(NumberNode.new(10))
    decl = VarDeclNode.new('foo', initializer)
    stmt = VarStatementNode.new([decl])
    block = BlockNode.new(SourceElementsNode.new([stmt]))

    node = ForInNode.new(ResolveNode.new('foo'), ResolveNode.new('bar'), block)
    assert_sexp([:for_in,
                [:resolve, 'foo'],
                [:resolve, 'bar'],
                [:block, [[:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]]]]
    ], node)
  end
end
