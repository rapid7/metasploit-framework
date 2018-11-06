require File.dirname(__FILE__) + "/../helper"

class Expressions_11_5_1_Test < ECMAScriptTestCase
  def test_nan_times_nan
    js_assert_equal("Number.NaN", "Number.NaN * Number.NaN")
  end

  def test_nan_times_1
    js_assert_equal("Number.NaN", "Number.NaN * 1")
  end

  def test_nan_1_times
    js_assert_equal("Number.NaN", "1 * Number.NaN")
  end

  def test_positive_inf_times_0
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY * 0")
  end

  def test_negative_inf_times_0
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY * 0")
  end

  def test_0_times_positive_inf
    js_assert_equal("Number.NaN", "0 * Number.POSITIVE_INFINITY")
  end

  def test_0_times_negative_inf
    js_assert_equal("Number.NaN", "0 * Number.NEGATIVE_INFINITY")
  end

  def test_0_times_0
    js_assert_equal("0", "0 * 0")
  end

  def test_infinity_multiplication
    js_assert_equal("Number.POSITIVE_INFINITY", "Number.NEGATIVE_INFINITY * Number.NEGATIVE_INFINITY")
    js_assert_equal("Number.NEGATIVE_INFINITY",  "Number.POSITIVE_INFINITY * Number.NEGATIVE_INFINITY")
    js_assert_equal("Number.NEGATIVE_INFINITY",  "Number.NEGATIVE_INFINITY * Number.POSITIVE_INFINITY")
    js_assert_equal("Number.POSITIVE_INFINITY",  "Number.POSITIVE_INFINITY * Number.POSITIVE_INFINITY")
    js_assert_equal("Number.NEGATIVE_INFINITY",  "Number.NEGATIVE_INFINITY * 1")
    js_assert_equal("Number.POSITIVE_INFINITY",  "Number.NEGATIVE_INFINITY * -1")
    js_assert_equal("Number.NEGATIVE_INFINITY",  "1 * Number.NEGATIVE_INFINITY")
    js_assert_equal("Number.POSITIVE_INFINITY",  "-1 * Number.NEGATIVE_INFINITY")
    js_assert_equal("Number.POSITIVE_INFINITY",  "Number.POSITIVE_INFINITY * 1")
    js_assert_equal("Number.NEGATIVE_INFINITY",  "Number.POSITIVE_INFINITY * -1")
    js_assert_equal("Number.POSITIVE_INFINITY",  "1 * Number.POSITIVE_INFINITY")
    js_assert_equal("Number.NEGATIVE_INFINITY",  "-1 * Number.POSITIVE_INFINITY")
  end

end
