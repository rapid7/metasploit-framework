require File.dirname(__FILE__) + "/helper"

class WithNodeTest < NodeTestCase
  def test_to_sexp
    node = WithNode.new(ResolveNode.new('foo'), ResolveNode.new('bar'))
    assert_sexp([:with, [:resolve, 'foo'], [:resolve, 'bar']], node)
  end
end
