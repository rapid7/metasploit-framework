require File.dirname(__FILE__) + "/helper"

class PrefixNodeTest < NodeTestCase
  def test_to_sexp
    node = PrefixNode.new(NumberNode.new(10), '++')
    assert_sexp([:prefix, [:lit, 10], '++'], node)
  end
end
