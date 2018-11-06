require File.dirname(__FILE__) + "/helper"

class ResolveNodeTest < NodeTestCase
  def test_to_sexp
    node = ResolveNode.new('foo')
    assert_sexp [:resolve, 'foo'], node
  end

  def test_match
    node = ResolveNode.new('foo')
    node2 = ResolveNode.new('foo')
    assert(node =~ node2)

    assert(node !~ NumberNode.new(10))
  end

  def test_is_a
    node = ResolveNode.new('foo')
    node3 = ResolveNode.new('String')
    assert(node3 =~ node)
  end
end
