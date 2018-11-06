require File.dirname(__FILE__) + "/helper"

class LogicalOrNodeTest < NodeTestCase
  def test_to_sexp
    node = LogicalOrNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:or, [:lit, 5], [:lit, 10]], node)
  end
end
