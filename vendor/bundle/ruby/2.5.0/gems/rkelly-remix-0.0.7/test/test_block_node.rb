require File.dirname(__FILE__) + "/helper"

class BlockNodeTest < NodeTestCase
  def test_to_sexp
    initializer = AssignExprNode.new(NumberNode.new(10))
    var_foo = VarDeclNode.new('foo', initializer)

    node = BlockNode.new(SourceElementsNode.new([]))
    assert_sexp([:block, []], node)

    node = BlockNode.new(SourceElementsNode.new([var_foo]))
    assert_sexp([:block, [[:var_decl, :foo, [:assign, [:lit, 10]]]]], node)
  end
end
