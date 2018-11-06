require File.dirname(__FILE__) + "/helper"

class TestScopeChain < Test::Unit::TestCase
  def setup
    @scope_chain = RKelly::Runtime::ScopeChain.new
    scope_1 = RKelly::JS::Scope.new
    scope_1.properties[:foo] = 1
    scope_2 = RKelly::JS::Scope.new
    scope_2.properties[:bar] = 10
    @scope_chain << scope_1
    @scope_chain << scope_2
  end

  def test_global_object_in_chain
    assert @scope_chain.has_property?('NaN')
  end

  def test_has_property
    assert @scope_chain.has_property?(:foo)
    assert @scope_chain.has_property?(:bar)
    assert !@scope_chain.has_property?(:baz)
    @scope_chain.pop
    assert @scope_chain.has_property?(:bar).nil?
  end

  def test_find_property
    assert_equal(10, @scope_chain[:bar])
    assert_equal(1, @scope_chain[:foo])
    @scope_chain.pop
    assert(!@scope_chain.has_property?(:bar))
  end

  def test_add_property
    assert !@scope_chain.has_property?(:baz)
    @scope_chain[:baz] = 10
    assert @scope_chain.has_property?(:baz)
    @scope_chain.pop
    assert !@scope_chain.has_property?(:baz)
  end

  def test_chain_in_block
    assert !@scope_chain.has_property?(:baz)
    @scope_chain.new_scope { |chain|
      chain[:baz] = 10
      assert @scope_chain.has_property?(:baz)
      assert chain.has_property?(:baz)
    }
    assert @scope_chain.has_property?(:baz).nil?
  end
end
