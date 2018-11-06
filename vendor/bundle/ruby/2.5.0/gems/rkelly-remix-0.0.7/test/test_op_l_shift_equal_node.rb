require File.dirname(__FILE__) + "/helper"

class OpLShiftEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpLShiftEqualNode.new(resolve, number)
    assert_sexp([:op_lshift_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
