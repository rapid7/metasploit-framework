require File.dirname(__FILE__) + "/../helper"

# ECMA-262
# Section 15.1.1.3
class GlobalObject_15_1_1_3_Test < ECMAScriptTestCase
  def test_undefined
    js_assert_equal('void 0', 'undefined')
  end
end
