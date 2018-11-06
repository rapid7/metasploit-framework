require File.dirname(__FILE__) + "/../helper"

class Expressions_11_4_9_Test < ECMAScriptTestCase
  def test_not_null
    js_assert_equal("true", "!(null)")
  end

  def test_undefined
    js_assert_equal("true", "!(void 0)")
  end

  def test_false
    js_assert_equal("true", "!(false)")
  end

  def test_true
    js_assert_equal("false", "!(true)")
  end

  def test_zero
    js_assert_equal("true", "!(0)")
  end

  def test_negative_zero
    js_assert_equal("true", "!(-0)")
  end

  def test_nan
    js_assert_equal("true", "!(NaN)")
  end

  def test_infinity
    js_assert_equal("false", "!(Infinity)")
  end

  def test_negative_infinity
    js_assert_equal("false", "!(-Infinity)")
  end

  def test_math_pi
    js_assert_equal("false", "!(Math.PI)")
  end

  def test_1
    js_assert_equal("false", "!(1)")
  end

  def test_negative_1
    js_assert_equal("false", "!(-1)")
  end

  def test_empty_string
    js_assert_equal("true", "!('')")
  end

  def test_non_empty_string
    js_assert_equal("false", "!('a string')")
  end

  def test_empty_string_object
    js_assert_equal("false", "!(new String(''))")
  end

  def test_non_empty_string_object
    js_assert_equal("false", "!(new String('string'))")
  end

  def test_string_object
    js_assert_equal("false", "!(new String())")
  end

  def test_boolean_object
    js_assert_equal("false", "!(new Boolean(true))")
  end

  def test_false_boolean_object
    js_assert_equal("false", "!(new Boolean(false))")
  end

  def test_array_object
    js_assert_equal("false", "!(new Array())")
  end

  def test_stuff_in_array_object
    js_assert_equal("false", "!(new Array(1,2,3))")
  end

  def test_number_object
    js_assert_equal("false", "!(new Number())")
  end

  def test_number_object_0
    js_assert_equal("false", "!(new Number(0))")
  end

  def test_number_object_nan
    js_assert_equal("false", "!(new Number(NaN))")
  end

  def test_number_object_infinite
    js_assert_equal("false", "!(new Number(Infinity))")
  end
end
