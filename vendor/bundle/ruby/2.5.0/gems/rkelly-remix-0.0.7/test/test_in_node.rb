require File.dirname(__FILE__) + "/helper"

class InNodeTest < NodeTestCase
  def test_to_sexp
    node = InNode.new(NumberNode.new(5), ResolveNode.new('foo'))
    assert_sexp([:in, [:lit, 5], [:resolve, 'foo']], node)
  end
end
