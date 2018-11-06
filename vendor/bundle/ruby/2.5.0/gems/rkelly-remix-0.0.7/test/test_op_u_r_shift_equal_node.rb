require File.dirname(__FILE__) + "/helper"

class OpURShiftEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpURShiftEqualNode.new(resolve, number)
    assert_sexp([:op_urshift_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
