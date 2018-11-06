require File.dirname(__FILE__) + "/../helper"

class Expressions_11_5_2_Test < ECMAScriptTestCase
  def test_nan_divide
    js_assert_equal("Number.NaN", "Number.NaN / Number.NaN")
    js_assert_equal("Number.NaN", "Number.NaN / 1")
    js_assert_equal("Number.NaN", "1 / Number.NaN")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY / Number.NaN")
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY / Number.NaN")
  end


  def test_infinity_divided_by_infinity
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY / Number.NEGATIVE_INFINITY")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY / Number.NEGATIVE_INFINITY")
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY / Number.POSITIVE_INFINITY")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY / Number.POSITIVE_INFINITY")
  end

  def test_infinity_divided_by_0
    js_assert_equal("Number.POSITIVE_INFINITY", "Number.POSITIVE_INFINITY / 0")
    js_assert_equal("Number.NEGATIVE_INFINITY", "Number.NEGATIVE_INFINITY / 0")
  end

  def test_infinity_divided_by_1
    js_assert_equal("Number.NEGATIVE_INFINITY", "Number.NEGATIVE_INFINITY / 1")
    js_assert_equal("Number.POSITIVE_INFINITY", "Number.NEGATIVE_INFINITY / -1")
    js_assert_equal("Number.POSITIVE_INFINITY", "Number.POSITIVE_INFINITY / 1")
    js_assert_equal("Number.NEGATIVE_INFINITY", "Number.POSITIVE_INFINITY / -1")
  end

  def test_infinity_divided_by_max
    js_assert_equal("Number.NEGATIVE_INFINITY","Number.NEGATIVE_INFINITY / Number.MAX_VALUE")
    js_assert_equal("Number.POSITIVE_INFINITY","Number.NEGATIVE_INFINITY / -Number.MAX_VALUE")
    js_assert_equal("Number.POSITIVE_INFINITY","Number.POSITIVE_INFINITY / Number.MAX_VALUE")
    js_assert_equal("Number.NEGATIVE_INFINITY","Number.POSITIVE_INFINITY / -Number.MAX_VALUE")
  end

  def test_number_divided_by_infinity
    js_assert_equal("-0", "1 / Number.NEGATIVE_INFINITY")
    js_assert_equal("0", "1 / Number.POSITIVE_INFINITY")
    js_assert_equal("-0", "-1 / Number.POSITIVE_INFINITY")
    js_assert_equal("0", "-1 / Number.NEGATIVE_INFINITY")
  end

  def test_max_val_divided_by_infinity
    js_assert_equal("-0", "Number.MAX_VALUE / Number.NEGATIVE_INFINITY")
    js_assert_equal("0", "Number.MAX_VALUE / Number.POSITIVE_INFINITY")
    js_assert_equal("-0", "-Number.MAX_VALUE / Number.POSITIVE_INFINITY")
    js_assert_equal("0", "-Number.MAX_VALUE / Number.NEGATIVE_INFINITY")
  end

  def test_0_divide_by_0
    js_assert_equal("Number.NaN", "0 / -0")
    js_assert_equal("Number.NaN", "-0 / 0")
    js_assert_equal("Number.NaN", "-0 / -0")
    js_assert_equal("Number.NaN", "0 / 0")
  end

  def test_0_divide_by_number
    js_assert_equal("0", "0 / 1")
    js_assert_equal("-0", "0 / -1")
    js_assert_equal("-0", "-0 / 1")
    js_assert_equal("0", "-0 / -1")
  end

  def test_number_divide_by_0
    js_assert_equal("Number.POSITIVE_INFINITY", "1/0")
    js_assert_equal("Number.NEGATIVE_INFINITY", "1/-0")
    js_assert_equal("Number.NEGATIVE_INFINITY", "-1/0")
    js_assert_equal("Number.POSITIVE_INFINITY", "-1/-0")
  end

  def test_0_divide_by_infinity
    js_assert_equal("0", "0 / Number.POSITIVE_INFINITY")
    js_assert_equal("-0", "0 / Number.NEGATIVE_INFINITY")
    js_assert_equal("-0", "-0 / Number.POSITIVE_INFINITY")
    js_assert_equal("0", "-0 / Number.NEGATIVE_INFINITY")
  end
end
