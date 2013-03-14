require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class AssertionsBaseTest < Test::Unit::TestCase
  include StateMachine::Assertions
  
  def default_test
  end
end

class AssertValidKeysTest < AssertionsBaseTest
  def test_should_not_raise_exception_if_key_is_valid
    assert_nothing_raised { assert_valid_keys({:name => 'foo', :value => 'bar'}, :name, :value, :force) }
  end
  
  def test_should_raise_exception_if_key_is_invalid
    exception = assert_raise(ArgumentError) { assert_valid_keys({:name => 'foo', :value => 'bar', :invalid => true}, :name, :value, :force) }
    assert_equal 'Invalid key(s): invalid', exception.message
  end
end

class AssertExclusiveKeysTest < AssertionsBaseTest
  def test_should_not_raise_exception_if_no_keys_found
    assert_nothing_raised { assert_exclusive_keys({:on => :park}, :only, :except) }
  end
  
  def test_should_not_raise_exception_if_one_key_found
    assert_nothing_raised { assert_exclusive_keys({:only => :parked}, :only, :except) }
    assert_nothing_raised { assert_exclusive_keys({:except => :parked}, :only, :except) }
  end
  
  def test_should_raise_exception_if_two_keys_found
    exception = assert_raise(ArgumentError) { assert_exclusive_keys({:only => :parked, :except => :parked}, :only, :except) }
    assert_equal 'Conflicting keys: only, except', exception.message
  end
  
  def test_should_raise_exception_if_multiple_keys_found
    exception = assert_raise(ArgumentError) { assert_exclusive_keys({:only => :parked, :except => :parked, :on => :park}, :only, :except, :with) }
    assert_equal 'Conflicting keys: only, except', exception.message
  end
end
