require File.dirname(__FILE__) + "/helper"

class NewExprNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    node = NewExprNode.new(resolve, ArgumentsNode.new([]))
    assert_sexp([:new_expr, [:resolve, 'foo'], [:args, []]], node)
  end
end
