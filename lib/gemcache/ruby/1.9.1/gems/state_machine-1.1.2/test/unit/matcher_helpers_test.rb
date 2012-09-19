require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class MatcherHelpersAllTest < Test::Unit::TestCase
  include StateMachine::MatcherHelpers
  
  def setup
    @matcher = all
  end
  
  def test_should_build_an_all_matcher
    assert_equal StateMachine::AllMatcher.instance, @matcher
  end
end

class MatcherHelpersAnyTest < Test::Unit::TestCase
  include StateMachine::MatcherHelpers
  
  def setup
    @matcher = any
  end
  
  def test_should_build_an_all_matcher
    assert_equal StateMachine::AllMatcher.instance, @matcher
  end
end

class MatcherHelpersSameTest < Test::Unit::TestCase
  include StateMachine::MatcherHelpers
  
  def setup
    @matcher = same
  end
  
  def test_should_build_a_loopback_matcher
    assert_equal StateMachine::LoopbackMatcher.instance, @matcher
  end
end
