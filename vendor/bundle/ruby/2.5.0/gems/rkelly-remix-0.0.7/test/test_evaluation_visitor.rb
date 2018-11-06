require File.dirname(__FILE__) + "/helper"

class EvaluationVisitorTest < Test::Unit::TestCase
  def setup
    @parser = RKelly::Parser.new
    @scope = RKelly::Runtime::ScopeChain.new
    @visitor = RKelly::Visitors::EvaluationVisitor.new(@scope)
  end

  def assert_properties(actual, js_code)
    tree = @parser.parse(js_code)
    @visitor.accept(tree)
    actual.each do |property, value|
      assert @visitor.scope_chain.has_property?(property)
      assert_equal value, @visitor.scope_chain[property].value
    end
  end

  def test_variable
    assert_properties({
      'foo' => 10,
    }, 'var foo = 10;')
  end

  def test_add
    assert_properties({
      'foo' => 6,
    }, 'var foo = 1 + 5;')
  end

  def test_subtract
    assert_properties({
      'foo' => 3,
    }, 'var foo = 4 - 1;')
  end

  def test_multiply
    assert_properties({
      'foo' => 8,
    }, 'var foo = 4 * 2;')
  end

  def test_divide
    assert_properties({
      'foo' => 2,
    }, 'var foo = 4 / 2;')
  end

  def test_a_bunch
    assert_properties({
      'foo' => 2,
    }, 'var foo = 1 + 2 * 2 / 4;')
  end

  def test_add_resolve
    assert_properties({
      'foo' => 3,
    }, 'foo = 1 + 2;')
  end

  def test_plus_equal
    assert_properties({
      'foo' => 3,
    }, 'var foo = 1; foo += 2;')
  end
end
