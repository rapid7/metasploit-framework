require File.dirname(__FILE__) + "/helper"

class FunctionCallNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    args = ArgumentsNode.new([])
    node = FunctionCallNode.new(resolve, args)
    assert_sexp([:function_call, [:resolve, 'foo'], [:args, []]], node)
  end
end
