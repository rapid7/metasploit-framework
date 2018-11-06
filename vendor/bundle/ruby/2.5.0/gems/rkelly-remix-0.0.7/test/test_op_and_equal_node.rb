require File.dirname(__FILE__) + "/helper"

class OpAndEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpAndEqualNode.new(resolve, number)
    assert_sexp([:op_and_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
