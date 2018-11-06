require File.dirname(__FILE__) + "/helper"

class CommaNodeTest < NodeTestCase
  def test_to_sexp
    left = OpEqualNode.new(ResolveNode.new('foo'), NumberNode.new(10))
    right = OpEqualNode.new(ResolveNode.new('bar'), NumberNode.new(11))
    node = CommaNode.new(left, right)
    assert_sexp([:comma,
                [:op_equal, [:resolve, 'foo'], [:lit, 10]],
                [:op_equal, [:resolve, 'bar'], [:lit, 11]]],
                node)
  end
end
