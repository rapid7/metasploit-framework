require File.dirname(__FILE__) + "/helper"

class LabelNodeTest < NodeTestCase
  def test_to_sexp
    initializer = AssignExprNode.new(NumberNode.new(10))
    var = VarDeclNode.new('bar', initializer)
    node = LabelNode.new('foo', var)
    assert_sexp(
                [:label, :foo,
                  [:var_decl, :bar, [:assign, [:lit, 10]]],
                ], node)
  end
end
