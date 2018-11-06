require File.dirname(__FILE__) + "/helper"

class PostfixNodeTest < NodeTestCase
  def test_to_sexp
    node = PostfixNode.new(NumberNode.new(10), '++')
    assert_sexp([:postfix, [:lit, 10], '++'], node)
  end
end
