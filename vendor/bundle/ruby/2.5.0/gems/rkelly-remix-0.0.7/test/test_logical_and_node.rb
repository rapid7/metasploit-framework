require File.dirname(__FILE__) + "/helper"

class LogicalAndNodeTest < NodeTestCase
  def test_to_sexp
    node = LogicalAndNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:and, [:lit, 5], [:lit, 10]], node)
  end
end
