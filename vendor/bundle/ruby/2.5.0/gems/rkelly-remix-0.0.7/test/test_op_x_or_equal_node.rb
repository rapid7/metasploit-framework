require File.dirname(__FILE__) + "/helper"

class OpXOrEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpXOrEqualNode.new(resolve, number)
    assert_sexp([:op_xor_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
