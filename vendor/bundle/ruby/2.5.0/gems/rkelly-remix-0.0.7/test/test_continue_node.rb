require File.dirname(__FILE__) + "/helper"

class ContinueNodeTest < NodeTestCase
  def test_to_sexp
    node = ContinueNode.new(nil)
    assert_sexp([:continue], node)

    node = ContinueNode.new('foo')
    assert_sexp([:continue, 'foo'], node)
  end
end
