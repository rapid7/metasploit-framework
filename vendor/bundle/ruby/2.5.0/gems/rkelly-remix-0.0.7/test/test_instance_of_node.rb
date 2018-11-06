require File.dirname(__FILE__) + "/helper"

class InstanceOfNodeTest < NodeTestCase
  def test_to_sexp
    node = InstanceOfNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:instance_of, [:lit, 5], [:lit, 10]], node)
  end
end
