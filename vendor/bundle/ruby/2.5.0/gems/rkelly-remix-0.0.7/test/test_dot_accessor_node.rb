require File.dirname(__FILE__) + "/helper"

class DotAccessorNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    node = DotAccessorNode.new(resolve, 'bar')
    assert_sexp([:dot_access, [:resolve, 'foo'], 'bar', ], node)
  end
end
