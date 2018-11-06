require File.dirname(__FILE__) + "/../helper"

class Object_15_2_1_2_Test < ECMAScriptTestCase
  def test_object_value_of
    @runtime.execute("
                     var MYOB = Object();
                     assert_equal(MYOB, MYOB.valueOf());
                     ")
  end

  def test_object_type_of
    js_assert_equal("'object'", 'typeof Object()')
  end

  def test_object_to_string
    @runtime.execute("
                     var MYOB = Object();
                     assert_equal('[object Object]', MYOB.toString());
                     ")
  end
end
