require File.dirname(__FILE__) + "/helper"

class VoidNodeTest < NodeTestCase
  def test_to_sexp
    node = VoidNode.new(ResolveNode.new('foo'))
    assert_sexp([:void, [:resolve, 'foo']], node)
  end
end
