require File.dirname(__FILE__) + "/helper"

class ForNodeTest < NodeTestCase
  def test_failure
    initializer = AssignExprNode.new(NumberNode.new(10))
    decl = VarDeclNode.new('foo', initializer)
    stmt = VarStatementNode.new([decl])

    compare = LessNode.new(ResolveNode.new('foo'), NumberNode.new(10))
    exec = PostfixNode.new(ResolveNode.new('foo'), '++')

    block = BlockNode.new(SourceElementsNode.new([stmt]))

    node = ForNode.new(nil, nil, nil, block)
    assert_sexp([:for, nil, nil, nil, [:block, [[:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]]]]], node)

    node = ForNode.new(stmt, compare, exec, block)
    assert_sexp([:for,
                [:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]],
                [:less, [:resolve, 'foo'], [:lit, 10]],
                [:postfix, [:resolve, 'foo'], '++'],
                [:block, [[:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]]]]], node)
  end
end
