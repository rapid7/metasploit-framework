require File.dirname(__FILE__) + "/helper"

class FalseNodeTest < NodeTestCase
  def test_to_sexp
    node = FalseNode.new('false')
    assert_sexp [:false], node
  end
end
