require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class StateCollectionByDefaultTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @states = StateMachine::StateCollection.new(@machine)
  end
  
  def test_should_not_have_any_nodes
    assert_equal 0, @states.length
  end
  
  def test_should_have_a_machine
    assert_equal @machine, @states.machine
  end
  
  def test_should_be_empty_by_priority
    assert_equal [], @states.by_priority
  end
end

class StateCollectionTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @states = StateMachine::StateCollection.new(@machine)
    
    @states << @nil = StateMachine::State.new(@machine, nil)
    @states << @parked = StateMachine::State.new(@machine, :parked)
    @states << @idling = StateMachine::State.new(@machine, :idling)
    @machine.states.concat(@states)
    
    @object = @klass.new
  end
  
  def test_should_index_by_name
    assert_equal @parked, @states[:parked, :name]
  end
  
  def test_should_index_by_name_by_default
    assert_equal @parked, @states[:parked]
  end
  
  def test_should_index_by_string_name
    assert_equal @parked, @states['parked']
  end
  
  def test_should_index_by_qualified_name
    assert_equal @parked, @states[:parked, :qualified_name]
  end
  
  def test_should_index_by_string_qualified_name
    assert_equal @parked, @states['parked', :qualified_name]
  end
  
  def test_should_index_by_value
    assert_equal @parked, @states['parked', :value]
  end
  
  def test_should_not_match_if_value_does_not_match
    assert !@states.matches?(@object, :parked)
    assert !@states.matches?(@object, :idling)
  end
  
  def test_should_match_if_value_matches
    assert @states.matches?(@object, nil)
  end
  
  def test_raise_exception_if_matching_invalid_state
    assert_raise(IndexError) { @states.matches?(@object, :invalid) }
  end
  
  def test_should_find_state_for_object_if_value_is_known
    @object.state = 'parked'
    assert_equal @parked, @states.match(@object)
  end
  
  def test_should_find_bang_state_for_object_if_value_is_known
    @object.state = 'parked'
    assert_equal @parked, @states.match!(@object)
  end
  
  def test_should_not_find_state_for_object_with_unknown_value
    @object.state = 'invalid'
    assert_nil @states.match(@object)
  end
  
  def test_should_raise_exception_if_finding_bang_state_for_object_with_unknown_value
    @object.state = 'invalid'
    exception = assert_raise(ArgumentError) { @states.match!(@object) }
    assert_equal '"invalid" is not a known state value', exception.message
  end
end

class StateCollectionStringTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @states = StateMachine::StateCollection.new(@machine)
    
    @states << @nil = StateMachine::State.new(@machine, nil)
    @states << @parked = StateMachine::State.new(@machine, 'parked')
    @machine.states.concat(@states)
    
    @object = @klass.new
  end
  
  def test_should_index_by_name
    assert_equal @parked, @states['parked', :name]
  end
  
  def test_should_index_by_name_by_default
    assert_equal @parked, @states['parked']
  end
  
  def test_should_index_by_symbol_name
    assert_equal @parked, @states[:parked]
  end
  
  def test_should_index_by_qualified_name
    assert_equal @parked, @states['parked', :qualified_name]
  end
  
  def test_should_index_by_symbol_qualified_name
    assert_equal @parked, @states[:parked, :qualified_name]
  end
end

class StateCollectionWithNamespaceTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :namespace => 'vehicle')
    @states = StateMachine::StateCollection.new(@machine)
    
    @states << @state = StateMachine::State.new(@machine, :parked)
    @machine.states.concat(@states)
  end
  
  def test_should_index_by_name
    assert_equal @state, @states[:parked, :name]
  end
  
  def test_should_index_by_qualified_name
    assert_equal @state, @states[:vehicle_parked, :qualified_name]
  end
end

class StateCollectionWithCustomStateValuesTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @states = StateMachine::StateCollection.new(@machine)
    
    @states << @state = StateMachine::State.new(@machine, :parked, :value => 1)
    @machine.states.concat(@states)
    
    @object = @klass.new
    @object.state = 1
  end
  
  def test_should_match_if_value_matches
    assert @states.matches?(@object, :parked)
  end
  
  def test_should_not_match_if_value_does_not_match
    @object.state = 2
    assert !@states.matches?(@object, :parked)
  end
  
  def test_should_find_state_for_object_if_value_is_known
    assert_equal @state, @states.match(@object)
  end
end

class StateCollectionWithStateMatchersTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @states = StateMachine::StateCollection.new(@machine)
    
    @states << @state = StateMachine::State.new(@machine, :parked, :if => lambda {|value| !value.nil?})
    @machine.states.concat(@states)
    
    @object = @klass.new
    @object.state = 1
  end
  
  def test_should_match_if_value_matches
    assert @states.matches?(@object, :parked)
  end
  
  def test_should_not_match_if_value_does_not_match
    @object.state = nil
    assert !@states.matches?(@object, :parked)
  end
  
  def test_should_find_state_for_object_if_value_is_known
    assert_equal @state, @states.match(@object)
  end
end

class StateCollectionWithInitialStateTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @states = StateMachine::StateCollection.new(@machine)
    
    @states << @parked = StateMachine::State.new(@machine, :parked)
    @states << @idling = StateMachine::State.new(@machine, :idling)
    @machine.states.concat(@states)
    
    @parked.initial = true
  end
  
  def test_should_order_state_before_transition_states
    @machine.event :ignite do
      transition :to => :idling
    end
    assert_equal [@parked, @idling], @states.by_priority
  end
  
  def test_should_order_state_before_states_with_behaviors
    @idling.context do
      def speed
        0
      end
    end
    assert_equal [@parked, @idling], @states.by_priority
  end
  
  def test_should_order_state_before_other_states
    assert_equal [@parked, @idling], @states.by_priority
  end
  
  def test_should_order_state_before_callback_states
    @machine.before_transition :from => :idling, :do => lambda {}
    assert_equal [@parked, @idling], @states.by_priority
  end
end

class StateCollectionWithStateBehaviorsTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @states = StateMachine::StateCollection.new(@machine)
    
    @states << @parked = StateMachine::State.new(@machine, :parked)
    @states << @idling = StateMachine::State.new(@machine, :idling)
    @machine.states.concat(@states)
    
    @idling.context do
      def speed
        0
      end
    end
  end
  
  def test_should_order_states_after_initial_state
    @parked.initial = true
    assert_equal [@parked, @idling], @states.by_priority
  end
  
  def test_should_order_states_after_transition_states
    @machine.event :ignite do
      transition :from => :parked
    end
    assert_equal [@parked, @idling], @states.by_priority
  end
  
  def test_should_order_states_before_other_states
    assert_equal [@idling, @parked], @states.by_priority
  end
  
  def test_should_order_state_before_callback_states
    @machine.before_transition :from => :parked, :do => lambda {}
    assert_equal [@idling, @parked], @states.by_priority
  end
end

class StateCollectionWithEventTransitionsTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @states = StateMachine::StateCollection.new(@machine)
    
    @states << @parked = StateMachine::State.new(@machine, :parked)
    @states << @idling = StateMachine::State.new(@machine, :idling)
    @machine.states.concat(@states)
    
    @machine.event :ignite do
      transition :to => :idling
    end
  end
  
  def test_should_order_states_after_initial_state
    @parked.initial = true
    assert_equal [@parked, @idling], @states.by_priority
  end
  
  def test_should_order_states_before_states_with_behaviors
    @parked.context do
      def speed
        0
      end
    end
    assert_equal [@idling, @parked], @states.by_priority
  end
  
  def test_should_order_states_before_other_states
    assert_equal [@idling, @parked], @states.by_priority
  end
  
  def test_should_order_state_before_callback_states
    @machine.before_transition :from => :parked, :do => lambda {}
    assert_equal [@idling, @parked], @states.by_priority
  end
end

class StateCollectionWithTransitionCallbacksTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @states = StateMachine::StateCollection.new(@machine)
    
    @states << @parked = StateMachine::State.new(@machine, :parked)
    @states << @idling = StateMachine::State.new(@machine, :idling)
    @machine.states.concat(@states)
    
    @machine.before_transition :to => :idling, :do => lambda {}
  end
  
  def test_should_order_states_after_initial_state
    @parked.initial = true
    assert_equal [@parked, @idling], @states.by_priority
  end
  
  def test_should_order_states_after_transition_states
    @machine.event :ignite do
      transition :from => :parked
    end
    assert_equal [@parked, @idling], @states.by_priority
  end
  
  def test_should_order_states_after_states_with_behaviors
    @parked.context do
      def speed
        0
      end
    end
    assert_equal [@parked, @idling], @states.by_priority
  end
  
  def test_should_order_states_after_other_states
    assert_equal [@parked, @idling], @states.by_priority
  end
end
