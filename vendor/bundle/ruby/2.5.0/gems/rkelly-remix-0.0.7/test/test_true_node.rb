require File.dirname(__FILE__) + "/helper"

class TrueNodeTest < NodeTestCase
  def test_to_sexp
    node = TrueNode.new('true')
    assert_sexp [:true], node
  end
end
