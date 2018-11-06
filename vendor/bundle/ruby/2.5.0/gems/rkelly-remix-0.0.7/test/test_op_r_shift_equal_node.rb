require File.dirname(__FILE__) + "/helper"

class OpRShiftEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpRShiftEqualNode.new(resolve, number)
    assert_sexp([:op_rshift_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
