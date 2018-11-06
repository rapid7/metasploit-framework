require File.dirname(__FILE__) + "/helper"

class FunctionVisitorTest < Test::Unit::TestCase
  def setup
    @parser = RKelly::Parser.new
    @scope = RKelly::Runtime::ScopeChain.new
    @visitor = RKelly::Visitors::FunctionVisitor.new(@scope)
  end

  def test_function
    tree = @parser.parse('function foo() { var x = 10; }')
    @visitor.accept(tree)
    assert @visitor.scope_chain['foo']

    tree = @parser.parse('function foo() { var x = 10; function bar() {}; }')
    @visitor.accept(tree)
    assert @visitor.scope_chain['foo']
    assert !@visitor.scope_chain.has_property?('bar')
  end

  def test_function_call
    tree = @parser.parse('var x = foo(); function foo() { return 10; }')
    @visitor.accept(tree)
    assert @visitor.scope_chain['foo']
  end
end
