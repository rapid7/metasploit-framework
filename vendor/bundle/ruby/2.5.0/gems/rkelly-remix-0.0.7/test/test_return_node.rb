require File.dirname(__FILE__) + "/helper"

class ReturnNodeTest < NodeTestCase
  def test_to_sexp
    node = ReturnNode.new(nil)
    assert_sexp([:return], node)

    node = ReturnNode.new(NumberNode.new(10))
    assert_sexp([:return, [:lit, 10]], node)
  end
end
