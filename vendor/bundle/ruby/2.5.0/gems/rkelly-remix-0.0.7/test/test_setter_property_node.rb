require File.dirname(__FILE__) + "/helper"

class SetterPropertyNodeTest < NodeTestCase
  def test_to_sexp
    body = FunctionBodyNode.new(SourceElementsNode.new([]))
    function = FunctionExprNode.new(nil, body)
    node = SetterPropertyNode.new('foo', function)
    assert_sexp([:setter, :foo, [:func_expr, nil, [], [:func_body, []]]], node)
  end
end
