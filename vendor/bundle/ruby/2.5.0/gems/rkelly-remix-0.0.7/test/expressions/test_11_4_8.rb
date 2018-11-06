require File.dirname(__FILE__) + "/../helper"

class Expressions_11_4_8_Test < ECMAScriptTestCase
  def test_positive_not
    0.upto(34) do |number|
      js_assert_equal(~to_int_32(2 ** number), "~#{2 ** number}")
    end
  end

  def test_negative_not
    0.upto(34) do |number|
      js_assert_equal(~to_int_32(-(2 ** number)), "~(#{-(2 ** number)})")
    end
  end

  def to_int_32(value)
    return value if value == 0
    if value.respond_to?(:nan?) && (value.nan? || value.infinite?)
      return 0
    end
    value = ((value < 0 ? -1 : 1) * value.abs.floor) % (2 ** 32)
    if value >= 2 ** 31
      value - (2 ** 32)
    else
      value
    end
  end
end
