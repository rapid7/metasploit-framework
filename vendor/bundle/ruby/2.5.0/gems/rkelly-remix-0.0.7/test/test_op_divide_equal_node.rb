require File.dirname(__FILE__) + "/helper"

class OpDivideEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpDivideEqualNode.new(resolve, number)
    assert_sexp([:op_divide_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
