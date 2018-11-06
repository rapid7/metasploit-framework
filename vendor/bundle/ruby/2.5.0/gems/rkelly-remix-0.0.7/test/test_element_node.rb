require File.dirname(__FILE__) + "/helper"

class ElementNodeTest < NodeTestCase
  def test_to_sexp
    node = ElementNode.new(NumberNode.new(10))
    assert_sexp([:element, [:lit, 10]], node)
  end
end
