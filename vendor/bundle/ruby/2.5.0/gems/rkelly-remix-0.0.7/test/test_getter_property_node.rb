require File.dirname(__FILE__) + "/helper"

class GetterPropertyNodeTest < NodeTestCase
  def test_to_sexp
    body = FunctionBodyNode.new(SourceElementsNode.new([]))
    function = FunctionExprNode.new(nil, body)
    node = GetterPropertyNode.new('foo', function)
    assert_sexp([:getter, :foo, [:func_expr, nil, [], [:func_body, []]]], node)
  end
end
