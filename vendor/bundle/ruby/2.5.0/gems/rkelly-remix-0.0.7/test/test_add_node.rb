require File.dirname(__FILE__) + "/helper"

class AddNodeTest < NodeTestCase
  def test_to_sexp
    node = AddNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:add, [:lit, 5], [:lit, 10]], node)
  end
end
