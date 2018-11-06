require File.dirname(__FILE__) + "/helper"

class ThisNodeTest < NodeTestCase
  def test_to_sexp
    node = ThisNode.new('this')
    assert_sexp([:this], node)
  end
end
