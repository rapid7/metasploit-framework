dir = File.dirname(__FILE__)
require File.expand_path("#{dir}/test_helper")

require File.expand_path("#{dir}/arithmetic_node_classes")
Treetop.load File.expand_path("#{dir}/arithmetic")

class ArithmeticParserTest < Test::Unit::TestCase
  include ParserTestHelper
  
  def setup
    @parser = ArithmeticParser.new
  end
  
  def test_number
    assert_equal 0, parse('0').eval
    assert_equal 1, parse('1').eval
    assert_equal 123, parse('123').eval
  end
  
  def test_variable
    assert_equal 0, parse('x').eval('x' => 0)
    assert_equal 3, parse('x').eval('x' => 3)
    assert_equal 10, parse('y').eval('y' => 10)
  end
  
  def test_addition
    assert_equal 10, parse('x + 5').eval('x' => 5)
  end
  
  def test_subtraction
    assert_equal 0, parse('x - 5').eval('x' => 5)
  end
  
  def test_multiplication
    assert_equal 6, parse('x * 2').eval('x' => 3)
  end
  
  def test_division
    assert_equal 3, parse('x / 2').eval('x' => 6)
  end
  
  def test_order_of_operations
    assert_equal 11, parse('1 + 2 * 3 + 4').eval
  end
  
  def test_left_to_right
    assert_equal 2, parse('5 - 2 - 1').eval
  end
  
  def test_parentheses
    assert_equal 25, parse('(5 + x) * (10 - y)').eval('x' => 0, 'y' => 5)
  end
  
  def test_equality
    assert parse('4 == 4').eval
    assert !parse('4 == 3').eval
  end
end
