require File.dirname(__FILE__) + "/helper"

class ObjectLiteralNodeTest < NodeTestCase
  def test_to_sexp
    property = PropertyNode.new('foo', NumberNode.new(10))
    node = ObjectLiteralNode.new([property])
    assert_sexp([:object, [[:property, :foo, [:lit, 10]]]], node)
  end
end
