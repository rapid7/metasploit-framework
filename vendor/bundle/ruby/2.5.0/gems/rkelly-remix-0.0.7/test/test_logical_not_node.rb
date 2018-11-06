require File.dirname(__FILE__) + "/helper"

class LogicalNotNodeTest < NodeTestCase
  def test_to_sexp
    node = LogicalNotNode.new(NumberNode.new(10))
    assert_sexp([:not, [:lit, 10]], node)
  end
end
