require File.dirname(__FILE__) + "/helper"

class ArrayNodeTest < NodeTestCase
  def test_to_sexp
    element = ElementNode.new(NumberNode.new(10))
    node = ArrayNode.new([element])
    assert_sexp([:array, [[:element, [:lit, 10]]]], node)
  end
end
