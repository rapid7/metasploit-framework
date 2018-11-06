require File.dirname(__FILE__) + "/helper"

class PointcutVisitorTest < Test::Unit::TestCase
  include RKelly::Visitors
  include RKelly::Nodes

  def setup
    @parser = RKelly::Parser.new
  end

  def test_visit_NumberNode
    ast = @parser.parse('Element.update(10, 10)')
    assert_equal(2, ast.pointcut('10').matches.length)
  end

  def test_visit_RegexpNode
    ast = @parser.parse('Element.update(/asdf/, /asdf/)')
    assert_equal(2, ast.pointcut('/asdf/').matches.length)
  end

  def test_visit_ContinueNode
    ast = @parser.parse('function foo() { continue; }')
    cut = ast.pointcut('continue')
    assert_equal(1, cut.matches.length)
    assert cut.matches.first.is_a?(ContinueNode)
  end

  def test_try_catch
    ast = @parser.parse('try { Element.update(10, 10); } catch(e) { }')
    assert_equal(1, ast.pointcut('Element.update(10, 10)').matches.length)
    ast = @parser.parse('try { Element.update("foo", "bar"); } catch(e) { }')
    assert_equal(1, ast.pointcut('Element.update(String, String)').matches.length)
  end
end
