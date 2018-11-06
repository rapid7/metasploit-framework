require File.dirname(__FILE__) + "/helper"

class BreakNodeTest < NodeTestCase
  def test_to_sexp
    node = BreakNode.new(nil)
    assert_sexp([:break], node)

    node = BreakNode.new('foo')
    assert_sexp([:break, 'foo'], node)
  end
end
