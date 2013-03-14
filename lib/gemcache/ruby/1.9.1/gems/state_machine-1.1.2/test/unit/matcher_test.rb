require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class MatcherByDefaultTest < Test::Unit::TestCase
  def setup
    @matcher = StateMachine::Matcher.new
  end
  
  def test_should_have_no_values
    assert_equal [], @matcher.values
  end
  
  def test_should_filter_all_values
    assert_equal [], @matcher.filter([:parked, :idling])
  end
end

class MatcherWithValueTest < Test::Unit::TestCase
  def setup
    @matcher = StateMachine::Matcher.new(nil)
  end
  
  def test_should_have_values
    assert_equal [nil], @matcher.values
  end
  
  def test_should_filter_unknown_values
    assert_equal [nil], @matcher.filter([nil, :parked])
  end
end

class MatcherWithMultipleValuesTest < Test::Unit::TestCase
  def setup
    @matcher = StateMachine::Matcher.new([:parked, :idling])
  end
  
  def test_should_have_values
    assert_equal [:parked, :idling], @matcher.values
  end
  
  def test_should_filter_unknown_values
    assert_equal [:parked], @matcher.filter([:parked, :first_gear])
  end
end

class AllMatcherTest < Test::Unit::TestCase
  def setup
    @matcher = StateMachine::AllMatcher.instance
  end
  
  def test_should_have_no_values
    assert_equal [], @matcher.values
  end
  
  def test_should_always_match
    [nil, :parked, :idling].each {|value| assert @matcher.matches?(value)}
  end
  
  def test_should_not_filter_any_values
    assert_equal [:parked, :idling], @matcher.filter([:parked, :idling])
  end
  
  def test_should_generate_blacklist_matcher_after_subtraction
    matcher = @matcher - [:parked, :idling]
    assert_instance_of StateMachine::BlacklistMatcher, matcher
    assert_equal [:parked, :idling], matcher.values
  end
  
  def test_should_have_a_description
    assert_equal 'all', @matcher.description
  end
end

class WhitelistMatcherTest < Test::Unit::TestCase
  def setup
    @matcher = StateMachine::WhitelistMatcher.new([:parked, :idling])
  end
  
  def test_should_have_values
    assert_equal [:parked, :idling], @matcher.values
  end
  
  def test_should_filter_unknown_values
    assert_equal [:parked, :idling], @matcher.filter([:parked, :idling, :first_gear])
  end
  
  def test_should_match_known_values
    assert @matcher.matches?(:parked)
  end
  
  def test_should_not_match_unknown_values
    assert !@matcher.matches?(:first_gear)
  end
  
  def test_should_have_a_description
    assert_equal '[:parked, :idling]', @matcher.description
    
    matcher = StateMachine::WhitelistMatcher.new([:parked])
    assert_equal ':parked', matcher.description
  end
end

class BlacklistMatcherTest < Test::Unit::TestCase
  def setup
    @matcher = StateMachine::BlacklistMatcher.new([:parked, :idling])
  end
  
  def test_should_have_values
    assert_equal [:parked, :idling], @matcher.values
  end
  
  def test_should_filter_known_values
    assert_equal [:first_gear], @matcher.filter([:parked, :idling, :first_gear])
  end
  
  def test_should_match_unknown_values
    assert @matcher.matches?(:first_gear)
  end
  
  def test_should_not_match_known_values
    assert !@matcher.matches?(:parked)
  end
  
  def test_should_have_a_description
    assert_equal 'all - [:parked, :idling]', @matcher.description
    
    matcher = StateMachine::BlacklistMatcher.new([:parked])
    assert_equal 'all - :parked', matcher.description
  end
end

class LoopbackMatcherTest < Test::Unit::TestCase
  def setup
    @matcher = StateMachine::LoopbackMatcher.instance
  end
  
  def test_should_have_no_values
    assert_equal [], @matcher.values
  end
  
  def test_should_filter_all_values
    assert_equal [], @matcher.filter([:parked, :idling])
  end
  
  def test_should_match_if_from_context_is_same
    assert @matcher.matches?(:parked, :from => :parked)
  end
  
  def test_should_not_match_if_from_context_is_different
    assert !@matcher.matches?(:parked, :from => :idling)
  end
  
  def test_should_have_a_description
    assert_equal 'same', @matcher.description
  end
end
