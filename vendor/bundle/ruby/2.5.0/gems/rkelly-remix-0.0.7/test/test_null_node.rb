require File.dirname(__FILE__) + "/helper"

class NullNodeTest < NodeTestCase
  def test_to_sexp
    node = NullNode.new('null')
    assert_sexp [:nil], node
  end
end
