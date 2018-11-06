require File.dirname(__FILE__) + "/helper"

class PropertyNodeTest < NodeTestCase
  def test_to_sexp
    node = PropertyNode.new('foo', NumberNode.new(10))
    assert_sexp([:property, :foo, [:lit, 10]], node)
  end
end
