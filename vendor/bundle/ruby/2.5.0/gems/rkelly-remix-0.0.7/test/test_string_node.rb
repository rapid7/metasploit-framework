require File.dirname(__FILE__) + "/helper"

class StringNodeTest < NodeTestCase
  def test_to_sexp
    node = StringNode.new('"asdf"')
    assert_sexp [:str, '"asdf"'], node
  end
end
