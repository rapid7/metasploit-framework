require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class PathByDefaultTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @object = @klass.new
    
    @path = StateMachine::Path.new(@object, @machine)
  end
  
  def test_should_have_an_object
    assert_equal @object, @path.object
  end
  
  def test_should_have_a_machine
    assert_equal @machine, @path.machine
  end
  
  def test_should_not_have_walked_anywhere
    assert_equal [], @path
  end
  
  def test_should_not_have_a_from_name
    assert_nil @path.from_name
  end
  
  def test_should_have_no_from_states
    assert_equal [], @path.from_states
  end
  
  def test_should_not_have_a_to_name
    assert_nil @path.to_name
  end
  
  def test_should_have_no_to_states
    assert_equal [], @path.to_states
  end
  
  def test_should_have_no_events
    assert_equal [], @path.events
  end
  
  def test_should_not_be_able_to_walk_anywhere
    walked = false
    @path.walk { walked = true }
    assert_equal false, walked
  end
  
  def test_should_not_be_complete
    assert_equal false, @path.complete?
  end
end

class PathTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @object = @klass.new
  end
  
  def test_should_raise_exception_if_invalid_option_specified
    exception = assert_raise(ArgumentError) {StateMachine::Path.new(@object, @machine, :invalid => true)}
    assert_equal 'Invalid key(s): invalid', exception.message
  end
end

class PathWithoutTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    
    @path = StateMachine::Path.new(@object, @machine)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
  end
  
  def test_should_not_be_able_to_walk_anywhere
    walked = false
    @path.walk { walked = true }
    assert_equal false, walked
  end
end

class PathWithTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @machine.event :ignite, :shift_up
    
    @object = @klass.new
    @object.state = 'parked'
    
    @path = StateMachine::Path.new(@object, @machine)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
      @shift_up_transition = StateMachine::Transition.new(@object, @machine, :shift_up, :idling, :first_gear)
    ])
  end
  
  def test_should_enumerate_transitions
    assert_equal [@ignite_transition, @shift_up_transition], @path
  end
  
  def test_should_have_a_from_name
    assert_equal :parked, @path.from_name
  end
  
  def test_should_have_from_states
    assert_equal [:parked, :idling], @path.from_states
  end
  
  def test_should_have_a_to_name
    assert_equal :first_gear, @path.to_name
  end
  
  def test_should_have_to_states
    assert_equal [:idling, :first_gear], @path.to_states
  end
  
  def test_should_have_events
    assert_equal [:ignite, :shift_up], @path.events
  end
  
  def test_should_not_be_able_to_walk_anywhere
    walked = false
    @path.walk { walked = true }
    assert_equal false, walked
  end
  
  def test_should_be_complete
    assert_equal true, @path.complete?
  end
end

class PathWithDuplicatesTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :park, :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    
    @path = StateMachine::Path.new(@object, @machine)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
      @park_transition = StateMachine::Transition.new(@object, @machine, :park, :idling, :parked),
      @ignite_again_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
  end
  
  def test_should_not_include_duplicates_in_from_states
    assert_equal [:parked, :idling], @path.from_states
  end
  
  def test_should_not_include_duplicates_in_to_states
    assert_equal [:idling, :parked], @path.to_states
  end
  
  def test_should_not_include_duplicates_in_events
    assert_equal [:ignite, :park], @path.events
  end
end

class PathWithAvailableTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @machine.event :ignite
    @machine.event :shift_up do
      transition :idling => :first_gear
    end
    @machine.event :park do
      transition :idling => :parked
    end
    
    @object = @klass.new
    @object.state = 'parked'
    
    @path = StateMachine::Path.new(@object, @machine)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
  end
  
  def test_should_not_be_complete
    assert !@path.complete?
  end
  
  def test_should_walk_each_available_transition
    paths = []
    @path.walk {|path| paths << path}
    
    assert_equal [
      [@ignite_transition, StateMachine::Transition.new(@object, @machine, :shift_up, :idling, :first_gear)],
      [@ignite_transition, StateMachine::Transition.new(@object, @machine, :park, :idling, :parked)]
    ], paths
  end
  
  def test_should_yield_path_instances_when_walking
    @path.walk do |path|
      assert_instance_of StateMachine::Path, path
    end
  end
  
  def test_should_not_modify_current_path_after_walking
    @path.walk {}
    assert_equal [@ignite_transition], @path
  end
  
  def test_should_not_modify_object_after_walking
    @path.walk {}
    assert_equal 'parked', @object.state
  end
end

class PathWithGuardedTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    @machine.event :shift_up do
      transition :idling => :first_gear, :if => lambda {false}
    end
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_not_walk_transitions_if_guard_enabled
    path = StateMachine::Path.new(@object, @machine)
    path.concat([
      ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    
    paths = []
    path.walk {|next_path| paths << next_path}
    
    assert_equal [], paths
  end
  
  def test_should_not_walk_transitions_if_guard_disabled
    path = StateMachine::Path.new(@object, @machine, :guard => false)
    path.concat([
      ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    
    paths = []
    path.walk {|next_path| paths << next_path}
    
    assert_equal [
      [ignite_transition, StateMachine::Transition.new(@object, @machine, :shift_up, :idling, :first_gear)]
    ], paths
  end
end

class PathWithEncounteredTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @machine.event :ignite do
      transition :parked => :idling
    end
    @machine.event :park do
      transition :idling => :parked
    end
    
    @object = @klass.new
    @object.state = 'parked'
    
    @path = StateMachine::Path.new(@object, @machine)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
      @park_transition = StateMachine::Transition.new(@object, @machine, :park, :idling, :parked)
    ])
  end
  
  def test_should_be_complete
    assert_equal true, @path.complete?
  end
  
  def test_should_not_be_able_to_walk
    walked = false
    @path.walk { walked = true }
    assert_equal false, walked
  end
end

class PathWithUnreachedTargetTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition :parked => :idling
    end
    
    @object = @klass.new
    @object.state = 'parked'
    
    @path = StateMachine::Path.new(@object, @machine, :target => :parked)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
  end
  
  def test_should_not_be_complete
    assert_equal false, @path.complete?
  end
  
  def test_should_not_be_able_to_walk
    walked = false
    @path.walk { walked = true }
    assert_equal false, walked
  end
end

class PathWithReachedTargetTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition :parked => :idling
    end
    @machine.event :park do
      transition :idling => :parked
    end
    
    @object = @klass.new
    @object.state = 'parked'
    
    @path = StateMachine::Path.new(@object, @machine, :target => :parked)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
      @park_transition = StateMachine::Transition.new(@object, @machine, :park, :idling, :parked)
    ])
  end
  
  def test_should_be_complete
    assert_equal true, @path.complete?
  end
  
  def test_should_not_be_able_to_walk
    walked = false
    @path.walk { walked = true }
    assert_equal false, walked
  end
end

class PathWithAvailableTransitionsAfterReachingTargetTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition :parked => :idling
    end
    @machine.event :shift_up do
      transition :parked => :first_gear
    end
    @machine.event :park do
      transition [:idling, :first_gear] => :parked
    end
    
    @object = @klass.new
    @object.state = 'parked'
    
    @path = StateMachine::Path.new(@object, @machine, :target => :parked)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
      @park_transition = StateMachine::Transition.new(@object, @machine, :park, :idling, :parked)
    ])
  end
  
  def test_should_be_complete
    assert_equal true, @path.complete?
  end
  
  def test_should_be_able_to_walk
    paths = []
    @path.walk {|path| paths << path}
    assert_equal [
      [@ignite_transition, @park_transition, StateMachine::Transition.new(@object, @machine, :shift_up, :parked, :first_gear)]
    ], paths
  end
end

class PathWithDeepTargetTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition :parked => :idling
    end
    @machine.event :shift_up do
      transition :parked => :first_gear
    end
    @machine.event :park do
      transition [:idling, :first_gear] => :parked
    end
    
    @object = @klass.new
    @object.state = 'parked'
    
    @path = StateMachine::Path.new(@object, @machine, :target => :parked)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
      @park_transition = StateMachine::Transition.new(@object, @machine, :park, :idling, :parked),
      @shift_up_transition = StateMachine::Transition.new(@object, @machine, :shift_up, :parked, :first_gear)
    ])
  end
  
  def test_should_not_be_complete
    assert_equal false, @path.complete?
  end
  
  def test_should_be_able_to_walk
    paths = []
    @path.walk {|path| paths << path}
    assert_equal [
      [@ignite_transition, @park_transition, @shift_up_transition, StateMachine::Transition.new(@object, @machine, :park, :first_gear, :parked)]
    ], paths
  end
end

class PathWithDeepTargetReachedTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition :parked => :idling
    end
    @machine.event :shift_up do
      transition :parked => :first_gear
    end
    @machine.event :park do
      transition [:idling, :first_gear] => :parked
    end
    
    @object = @klass.new
    @object.state = 'parked'
    
    @path = StateMachine::Path.new(@object, @machine, :target => :parked)
    @path.concat([
      @ignite_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
      @park_transition = StateMachine::Transition.new(@object, @machine, :park, :idling, :parked),
      @shift_up_transition = StateMachine::Transition.new(@object, @machine, :shift_up, :parked, :first_gear),
      @park_transition_2 = StateMachine::Transition.new(@object, @machine, :park, :first_gear, :parked)
    ])
  end
  
  def test_should_be_complete
    assert_equal true, @path.complete?
  end
  
  def test_should_not_be_able_to_walk
    walked = false
    @path.walk { walked = true }
    assert_equal false, walked
  end
  
  def test_should_not_be_able_to_walk_with_available_transitions
    @machine.event :park do
      transition :parked => same
    end
    
    walked = false
    @path.walk { walked = true }
    assert_equal false, walked
  end
end
