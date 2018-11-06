require File.dirname(__FILE__) + "/helper"

class NumberNodeTest < NodeTestCase
  def test_to_sexp
    node = NumberNode.new(10)
    assert_sexp [:lit, 10], node
  end
end
