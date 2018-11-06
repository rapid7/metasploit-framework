require File.dirname(__FILE__) + "/helper"

class ModulusNodeTest < NodeTestCase
  def test_to_sexp
    node = ModulusNode.new(NumberNode.new(5), NumberNode.new(10))
    assert_sexp([:modulus, [:lit, 5], [:lit, 10]], node)
  end
end
