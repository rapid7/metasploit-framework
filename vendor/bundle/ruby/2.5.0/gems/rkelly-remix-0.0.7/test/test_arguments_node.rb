require File.dirname(__FILE__) + "/helper"

class ArgumentsNodeTest < NodeTestCase
  def test_to_sexp
    node = ArgumentsNode.new([])
    assert_sexp([:args, []], node)
  end
end
