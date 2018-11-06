require File.dirname(__FILE__) + "/helper"

class VarDeclNodeTest < NodeTestCase
  def test_to_sexp
    initializer = AssignExprNode.new(NumberNode.new(10))
    node = VarDeclNode.new('foo', initializer)
    assert_sexp [:var_decl, :foo, [:assign, [:lit, 10]]], node

    node = VarDeclNode.new('foo', nil)
    assert_sexp [:var_decl, :foo, nil], node
  end

  def test_const_to_sexp
    initializer = AssignExprNode.new(NumberNode.new(10))
    node = VarDeclNode.new('foo', initializer, true)
    assert_sexp [:const_decl, :foo, [:assign, [:lit, 10]]], node

    node = VarDeclNode.new('foo', nil, true)
    assert_sexp [:const_decl, :foo, nil], node
  end
end
