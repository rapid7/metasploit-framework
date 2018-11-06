require File.dirname(__FILE__) + "/helper"

class OpModEqualNodeTest < NodeTestCase
  def test_to_sexp
    resolve = ResolveNode.new('foo')
    number  = NumberNode.new(10)
    node = OpModEqualNode.new(resolve, number)
    assert_sexp([:op_mod_equal, [:resolve, 'foo'], [:lit, 10]], node)
  end
end
