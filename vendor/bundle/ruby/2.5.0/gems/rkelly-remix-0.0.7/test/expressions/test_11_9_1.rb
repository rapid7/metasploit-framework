require File.dirname(__FILE__) + "/../helper"

class Expressions_11_9_1_Test < ExecuteTestCase
  def setup
    @runtime = RKelly::Runtime.new
  end

  def test_void_equal
    assert_execute({ 'x' => true }, "var x = void(0) == void(0);")
  end

  def test_void_equal_decl
    assert_execute({ 'z' => true }, "var x = 10; var y = 10; var z = x == y;")
  end

  def test_null_eql
    assert_execute({ 'x' => true }, "var x = null == null;")
  end
end
