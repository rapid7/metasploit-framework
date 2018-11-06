require File.dirname(__FILE__) + "/../helper"

class Expressions_11_4_2_Test < Test::Unit::TestCase
  def setup
    @runtime = RKelly::Runtime.new
  end

  def test_void_1
    scope_chain = @runtime.execute("var x = void(10);")
    assert scope_chain.has_property?('x')
    assert_equal :undefined, scope_chain['x'].value
  end
end
