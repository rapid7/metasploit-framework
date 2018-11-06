require File.dirname(__FILE__) + "/../helper"

class Expressions_11_6_1_1_Test < ECMAScriptTestCase
  def test_primitive_boolean
    js_assert_equal("1", "true + false")
  end

  def test_boolean_object
    js_assert_equal("1", "new Boolean(true) + new Boolean(false)")
  end

  def test_object_boolean_object
    js_assert_equal("1", "new Object(true) + new Object(false)")
  end

  def test_object_boolean_object_boolean
    js_assert_equal("1", "new Object(new Boolean(true)) + new Object(new Boolean(false))")
  end
end
