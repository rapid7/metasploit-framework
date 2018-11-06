require File.dirname(__FILE__) + "/helper"

class EmptyStatementNodeTest < NodeTestCase
  def test_to_to_sexp
    node = EmptyStatementNode.new(';')
    assert_sexp([:empty], node)
  end
end
