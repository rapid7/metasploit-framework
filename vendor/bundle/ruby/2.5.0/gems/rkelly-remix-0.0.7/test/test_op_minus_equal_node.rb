require File.dirname(__FILE__) + "/helper"

class OpMinusEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpMinusEqualNode.new(resolve, number)
    assert_sexp([:op_minus_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
