require File.dirname(__FILE__) + "/helper"

class BracketAccessorNodeTest < NodeTestCase
  def test_sexp
    resolve = ResolveNode.new('foo')
    index = NumberNode.new(10)
    node = BracketAccessorNode.new(resolve, index)
    assert_sexp(
      [:bracket_access,
        [:resolve, 'foo'],
        [:lit, 10],
      ],
      node
    )
  end
end
