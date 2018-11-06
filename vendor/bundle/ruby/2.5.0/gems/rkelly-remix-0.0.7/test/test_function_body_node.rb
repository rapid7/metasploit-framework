require File.dirname(__FILE__) + "/helper"

class FunctionBodyNodeTest < NodeTestCase
  def test_to_sexp
    node = FunctionBodyNode.new(SourceElementsNode.new([]))
    assert_sexp([:func_body, []], node)
  end
end
