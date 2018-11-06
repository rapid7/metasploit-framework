require File.dirname(__FILE__) + "/helper"

class OpMultiplyEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpMultiplyEqualNode.new(resolve, number)
    assert_sexp([:op_multiply_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
