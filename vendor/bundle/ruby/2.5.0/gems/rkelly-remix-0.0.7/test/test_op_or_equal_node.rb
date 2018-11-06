require File.dirname(__FILE__) + "/helper"

class OpOrEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpOrEqualNode.new(resolve, number)
    assert_sexp([:op_or_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
