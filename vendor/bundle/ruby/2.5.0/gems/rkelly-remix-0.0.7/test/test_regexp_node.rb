require File.dirname(__FILE__) + "/helper"

class RegexpNodeTest < NodeTestCase
  def test_to_sexp
    node = RegexpNode.new('/yay!/')
    assert_sexp [:lit, '/yay!/'], node
  end
end
