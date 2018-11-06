require File.dirname(__FILE__) + "/../helper"

class Expressions_11_5_3_Test < ECMAScriptTestCase
  def test_either_is_nan
    js_assert_equal("Number.NaN", "Number.NaN % Number.NaN")
    js_assert_equal("Number.NaN", "Number.NaN % 1")
    js_assert_equal("Number.NaN", "1 % Number.NaN")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY % Number.NaN")
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY % Number.NaN")
  end

  def test_infinity_mod_infinity
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY % Number.NEGATIVE_INFINITY")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY % Number.NEGATIVE_INFINITY")
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY % Number.POSITIVE_INFINITY")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY % Number.POSITIVE_INFINITY")
  end

  def test_infinity_mod_0
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY % 0")
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY % 0")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY % -0")
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY % -0")
  end

  def test_infinity_mod_1
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY % 1")
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY % -1")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY % 1")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY % -1")
  end

  def test_infinity_mod_max_value
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY % Number.MAX_VALUE")
    js_assert_equal("Number.NaN", "Number.NEGATIVE_INFINITY % -Number.MAX_VALUE")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY % Number.MAX_VALUE")
    js_assert_equal("Number.NaN", "Number.POSITIVE_INFINITY % -Number.MAX_VALUE")
  end

  def test_0_mod_0
    js_assert_equal("Number.NaN", "0 % -0")
    js_assert_equal("Number.NaN", "-0 % 0")
    js_assert_equal("Number.NaN", "-0 % -0")
    js_assert_equal("Number.NaN", "0 % 0")
  end

  def test_1_mod_0
    js_assert_equal("Number.NaN", "1%0")
    js_assert_equal("Number.NaN", "1%-0")
    js_assert_equal("Number.NaN", "-1%0")
    js_assert_equal("Number.NaN", "-1%-0")
  end

  def test_max_value_mod_0
    js_assert_equal("Number.NaN", "Number.MAX_VALUE%0")
    js_assert_equal("Number.NaN", "Number.MAX_VALUE%-0")
    js_assert_equal("Number.NaN", "-Number.MAX_VALUE%0")
    js_assert_equal("Number.NaN", "-Number.MAX_VALUE%-0")
  end

  def test_number_mod_infinity
    js_assert_equal("1", "1 % Number.NEGATIVE_INFINITY")
    js_assert_equal("1", "1 % Number.POSITIVE_INFINITY")
    js_assert_equal("-1", "-1 % Number.POSITIVE_INFINITY")
    js_assert_equal("-1", "-1 % Number.NEGATIVE_INFINITY")
  end

  def test_max_val_mod_infinity
    js_assert_equal("Number.MAX_VALUE", "Number.MAX_VALUE % Number.NEGATIVE_INFINITY")
    js_assert_equal("Number.MAX_VALUE", "Number.MAX_VALUE % Number.POSITIVE_INFINITY")
    js_assert_equal("-Number.MAX_VALUE", "-Number.MAX_VALUE % Number.POSITIVE_INFINITY")
    js_assert_equal("-Number.MAX_VALUE", "-Number.MAX_VALUE % Number.NEGATIVE_INFINITY")
  end

  def test_0_mod_infinity
    js_assert_equal("0", "0 % Number.POSITIVE_INFINITY")
    js_assert_equal("0", "0 % Number.NEGATIVE_INFINITY")
    js_assert_equal("-0", "-0 % Number.POSITIVE_INFINITY")
    js_assert_equal("-0", "-0 % Number.NEGATIVE_INFINITY")
  end

  def test_0_mod_1
    js_assert_equal("0", "0 % 1")
    js_assert_equal("-0", "0 % -1")
    js_assert_equal("-0", "-0 % 1")
    js_assert_equal("0", "-0 % -1")
  end
end
