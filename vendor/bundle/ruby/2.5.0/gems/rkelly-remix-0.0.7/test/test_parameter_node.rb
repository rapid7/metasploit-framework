require File.dirname(__FILE__) + "/helper"

class ParameterNodeTest < NodeTestCase
  def test_to_sexp
    node = ParameterNode.new('a')
    assert_sexp([:param, 'a'], node)
  end
end
