require File.dirname(__FILE__) + "/helper"

class ThrowNodeTest < NodeTestCase
  def test_to_sexp
    assert_sexp([:throw, [:lit, 10]], ThrowNode.new(NumberNode.new(10)))
  end
end
