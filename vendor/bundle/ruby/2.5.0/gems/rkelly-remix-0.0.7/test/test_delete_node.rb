require File.dirname(__FILE__) + "/helper"

class DeleteNodeTest < NodeTestCase
  def test_to_sexp
    node = DeleteNode.new(ResolveNode.new('foo'))
    assert_sexp([:delete, [:resolve, 'foo']], node)
  end
end
