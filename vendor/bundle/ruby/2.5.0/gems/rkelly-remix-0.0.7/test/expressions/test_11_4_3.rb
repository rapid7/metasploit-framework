require File.dirname(__FILE__) + "/../helper"

class Typeof_11_4_3_Test < ExecuteTestCase
  def setup
    @runtime = RKelly::Runtime.new
  end

  def test_typeof_null
    assert_execute({ 'x' => 'object' },
      "var x = typeof(null);")
  end

  def test_typeof_void_0
    assert_execute({ 'x' => 'undefined' },
      "var x = typeof(void(0));")
  end

  def test_typeof_true
    assert_execute({ 'x' => 'boolean' },
      "var x = typeof(true);")
  end

  def test_typeof_false
    assert_execute({ 'x' => 'boolean' },
      "var x = typeof(false);")
  end

  def test_typeof_nan
    assert_execute({ 'x' => 'number' },
      "var x = typeof(NaN);")
  end

  def test_typeof_zero
    assert_execute({ 'x' => 'number' }, "var x = typeof(0);")
  end

  def test_typeof_one
    assert_execute({ 'x' => 'number' }, "var x = typeof(1);")
  end

  def test_typeof_minus_one
    assert_execute({ 'x' => 'number' }, "var x = typeof(-1);")
  end

  def test_typeof_plus_one
    assert_execute({ 'x' => 'number' }, "var x = typeof(+1);")
  end

  def test_typeof_zero_string
    assert_execute({ 'x' => 'string' }, "var x = typeof('0');")
  end
end
