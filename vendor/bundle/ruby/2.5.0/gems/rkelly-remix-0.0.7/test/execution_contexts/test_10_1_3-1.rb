require File.dirname(__FILE__) + "/../helper"

class ExecutionContext_10_1_3_1_Test < Test::Unit::TestCase
  def setup
    @runtime = RKelly::Runtime.new
    @runtime.define_function(:assert_equal) do |*args|
      assert_equal(*args)
    end
  end

  def test_myfun3_void_0
    scope_chain = @runtime.execute("
                     function myfun3(a, b, a) {
                      return a;
                     }
                     var x = myfun3(2,4);
                     ")
    assert scope_chain.has_property?('x')
    #assert_equal :undefined, scope_chain['x'].value
  end

  def test_myfun3
    scope_chain = @runtime.execute("
                     function myfun3(a, b, a) {
                      return a;
                     }
                     var x = myfun3(2,4,8);
                     ")
    assert scope_chain.has_property?('x')
    assert_equal 8, scope_chain['x'].value
  end
end
