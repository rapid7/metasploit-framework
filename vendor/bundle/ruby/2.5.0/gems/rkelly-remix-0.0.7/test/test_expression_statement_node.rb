require File.dirname(__FILE__) + "/helper"

class ExpressionStatementNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    access = DotAccessorNode.new(resolve, 'bar')
    node = ExpressionStatementNode.new(access)
    assert_sexp([:expression, [:dot_access, [:resolve, 'foo'], 'bar', ]], node)
  end
end
