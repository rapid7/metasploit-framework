require File.dirname(__FILE__) + "/helper"

class TypeOfNodeTest < NodeTestCase
  def test_to_sexp
    node = TypeOfNode.new(ResolveNode.new('foo'))
    assert_sexp([:typeof, [:resolve, 'foo']], node)
  end
end
