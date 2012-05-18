require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class EventCollectionByDefaultTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @events = StateMachine::EventCollection.new(@machine)
  end
  
  def test_should_not_have_any_nodes
    assert_equal 0, @events.length
  end
  
  def test_should_have_a_machine
    assert_equal @machine, @events.machine
  end
  
  def test_should_not_have_any_valid_events_for_an_object
    assert @events.valid_for(@object).empty?
  end
  
  def test_should_not_have_any_transitions_for_an_object
    assert @events.transitions_for(@object).empty?
  end
end

class EventCollectionTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new, :namespace => 'alarm')
    @events = StateMachine::EventCollection.new(machine)
    
    @events << @open = StateMachine::Event.new(machine, :enable)
    machine.events.concat(@events)
  end
  
  def test_should_index_by_name
    assert_equal @open, @events[:enable, :name]
  end
  
  def test_should_index_by_name_by_default
    assert_equal @open, @events[:enable]
  end
  
  def test_should_index_by_string_name
    assert_equal @open, @events['enable']
  end
  
  def test_should_index_by_qualified_name
    assert_equal @open, @events[:enable_alarm, :qualified_name]
  end
  
  def test_should_index_by_string_qualified_name
    assert_equal @open, @events['enable_alarm', :qualified_name]
  end
end

class EventStringCollectionTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new, :namespace => 'alarm')
    @events = StateMachine::EventCollection.new(machine)
    
    @events << @open = StateMachine::Event.new(machine, 'enable')
    machine.events.concat(@events)
  end
  
  def test_should_index_by_name
    assert_equal @open, @events['enable', :name]
  end
  
  def test_should_index_by_name_by_default
    assert_equal @open, @events['enable']
  end
  
  def test_should_index_by_symbol_name
    assert_equal @open, @events[:enable]
  end
  
  def test_should_index_by_qualified_name
    assert_equal @open, @events['enable_alarm', :qualified_name]
  end
  
  def test_should_index_by_symbol_qualified_name
    assert_equal @open, @events[:enable_alarm, :qualified_name]
  end
end

class EventCollectionWithEventsWithTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @events = StateMachine::EventCollection.new(@machine)
    
    @machine.state :idling, :first_gear
    
    @events << @ignite = StateMachine::Event.new(@machine, :ignite)
    @ignite.transition :parked => :idling
    
    @events << @park = StateMachine::Event.new(@machine, :park)
    @park.transition :idling => :parked
    
    @events << @shift_up = StateMachine::Event.new(@machine, :shift_up)
    @shift_up.transition :parked => :first_gear
    @shift_up.transition :idling => :first_gear, :if => lambda{false}
    
    @machine.events.concat(@events)
    
    @object = @klass.new
  end
  
  def test_should_find_valid_events_based_on_current_state
    assert_equal [@ignite, @shift_up], @events.valid_for(@object)
  end
  
  def test_should_filter_valid_events_by_from_state
    assert_equal [@park], @events.valid_for(@object, :from => :idling)
  end
  
  def test_should_filter_valid_events_by_to_state
    assert_equal [@shift_up], @events.valid_for(@object, :to => :first_gear)
  end
  
  def test_should_filter_valid_events_by_event
    assert_equal [@ignite], @events.valid_for(@object, :on => :ignite)
  end
  
  def test_should_filter_valid_events_by_multiple_requirements
    assert_equal [], @events.valid_for(@object, :from => :idling, :to => :first_gear)
  end
  
  def test_should_allow_finding_valid_events_without_guards
    assert_equal [@shift_up], @events.valid_for(@object, :from => :idling, :to => :first_gear, :guard => false)
  end
  
  def test_should_find_valid_transitions_based_on_current_state
    assert_equal [
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
      StateMachine::Transition.new(@object, @machine, :shift_up, :parked, :first_gear)
    ], @events.transitions_for(@object)
  end
  
  def test_should_filter_valid_transitions_by_from_state
    assert_equal [StateMachine::Transition.new(@object, @machine, :park, :idling, :parked)], @events.transitions_for(@object, :from => :idling)
  end
  
  def test_should_filter_valid_transitions_by_to_state
    assert_equal [StateMachine::Transition.new(@object, @machine, :shift_up, :parked, :first_gear)], @events.transitions_for(@object, :to => :first_gear)
  end
  
  def test_should_filter_valid_transitions_by_event
    assert_equal [StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)], @events.transitions_for(@object, :on => :ignite)
  end
  
  def test_should_filter_valid_transitions_by_multiple_requirements
    assert_equal [], @events.transitions_for(@object, :from => :idling, :to => :first_gear)
  end
  
  def test_should_allow_finding_valid_transitions_without_guards
    assert_equal [StateMachine::Transition.new(@object, @machine, :shift_up, :idling, :first_gear)], @events.transitions_for(@object, :from => :idling, :to => :first_gear, :guard => false)
  end
end

class EventCollectionWithMultipleEventsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @events = StateMachine::EventCollection.new(@machine)
    
    @machine.state :first_gear
    @park, @shift_down = @machine.event :park, :shift_down
    
    @events << @park
    @park.transition :first_gear => :parked
    
    @events << @shift_down
    @shift_down.transition :first_gear => :parked
    
    @machine.events.concat(@events)
  end
  
  def test_should_only_include_all_valid_events_for_an_object
    object = @klass.new
    object.state = 'first_gear'
    assert_equal [@park, @shift_down], @events.valid_for(object)
  end
end

class EventCollectionWithoutMachineActionTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @events = StateMachine::EventCollection.new(@machine)
    @events << StateMachine::Event.new(@machine, :ignite)
    @machine.events.concat(@events)
    
    @object = @klass.new
  end
  
  def test_should_not_have_an_attribute_transition
    assert_nil @events.attribute_transition_for(@object)
  end
end

class EventCollectionAttributeWithMachineActionTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def save
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @events = StateMachine::EventCollection.new(@machine)
    
    @machine.state :parked, :idling
    @events << @ignite = StateMachine::Event.new(@machine, :ignite)
    @machine.events.concat(@events)
    
    @object = @klass.new
  end
  
  def test_should_not_have_transition_if_nil
    @object.state_event = nil
    assert_nil @events.attribute_transition_for(@object)
  end
  
  def test_should_not_have_transition_if_empty
    @object.state_event = ''
    assert_nil @events.attribute_transition_for(@object)
  end
  
  def test_should_have_invalid_transition_if_invalid_event_specified
    @object.state_event = 'invalid'
    assert_equal false, @events.attribute_transition_for(@object)
  end
  
  def test_should_have_invalid_transition_if_event_cannot_be_fired
    @object.state_event = 'ignite'
    assert_equal false, @events.attribute_transition_for(@object)
  end
  
  def test_should_have_valid_transition_if_event_can_be_fired
    @ignite.transition :parked => :idling
    @object.state_event = 'ignite'
    
    assert_instance_of StateMachine::Transition, @events.attribute_transition_for(@object)
  end
  
  def test_should_have_valid_transition_if_already_defined_in_transition_cache
    @ignite.transition :parked => :idling
    @object.state_event = nil
    @object.send(:state_event_transition=, transition = @ignite.transition_for(@object))
    
    assert_equal transition, @events.attribute_transition_for(@object)
  end
  
  def test_should_use_transition_cache_if_both_event_and_transition_are_present
    @ignite.transition :parked => :idling
    @object.state_event = 'ignite'
    @object.send(:state_event_transition=, transition = @ignite.transition_for(@object))
    
    assert_equal transition, @events.attribute_transition_for(@object)
  end
end

class EventCollectionAttributeWithNamespacedMachineTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def save
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :namespace => 'alarm', :initial => :active, :action => :save)
    @events = StateMachine::EventCollection.new(@machine)
    
    @machine.state :active, :off
    @events << @disable = StateMachine::Event.new(@machine, :disable)
    @machine.events.concat(@events)
    
    @object = @klass.new
  end
  
  def test_should_not_have_transition_if_nil
    @object.state_event = nil
    assert_nil @events.attribute_transition_for(@object)
  end
  
  def test_should_have_invalid_transition_if_event_cannot_be_fired
    @object.state_event = 'disable'
    assert_equal false, @events.attribute_transition_for(@object)
  end
  
  def test_should_have_valid_transition_if_event_can_be_fired
    @disable.transition :active => :off
    @object.state_event = 'disable'
    
    assert_instance_of StateMachine::Transition, @events.attribute_transition_for(@object)
  end
end

class EventCollectionWithValidationsTest < Test::Unit::TestCase
  def setup
    StateMachine::Integrations.const_set('Custom', Module.new do
      include StateMachine::Integrations::Base
      
      def invalidate(object, attribute, message, values = [])
        (object.errors ||= []) << generate_message(message, values)
      end
      
      def reset(object)
        object.errors = []
      end
    end)
    
    @klass = Class.new do
      attr_accessor :errors
      
      def initialize
        @errors = []
        super
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save, :integration => :custom)
    @events = StateMachine::EventCollection.new(@machine)
    
    @parked, @idling = @machine.state :parked, :idling
    @events << @ignite = StateMachine::Event.new(@machine, :ignite)
    @machine.events.concat(@events)
    
    @object = @klass.new
  end
  
  def test_should_invalidate_if_invalid_event_specified
    @object.state_event = 'invalid'
    @events.attribute_transition_for(@object, true)
    
    assert_equal ['is invalid'], @object.errors
  end
  
  def test_should_invalidate_if_event_cannot_be_fired
    @object.state = 'idling'
    @object.state_event = 'ignite'
    @events.attribute_transition_for(@object, true)
    
    assert_equal ['cannot transition when idling'], @object.errors
  end
  
  def test_should_invalidate_with_human_name_if_invalid_event_specified
    @idling.human_name = 'waiting'
    @object.state = 'idling'
    @object.state_event = 'ignite'
    @events.attribute_transition_for(@object, true)
    
    assert_equal ['cannot transition when waiting'], @object.errors
  end
  
  def test_should_not_invalidate_event_can_be_fired
    @ignite.transition :parked => :idling
    @object.state_event = 'ignite'
    @events.attribute_transition_for(@object, true)
    
    assert_equal [], @object.errors
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class EventCollectionWithCustomMachineAttributeTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def save
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :state, :attribute => :state_id, :initial => :parked, :action => :save)
    @events = StateMachine::EventCollection.new(@machine)
    
    @machine.state :parked, :idling
    @events << @ignite = StateMachine::Event.new(@machine, :ignite)
    @machine.events.concat(@events)
    
    @object = @klass.new
  end
  
  def test_should_not_have_transition_if_nil
    @object.state_event = nil
    assert_nil @events.attribute_transition_for(@object)
  end
  
  def test_should_have_valid_transition_if_event_can_be_fired
    @ignite.transition :parked => :idling
    @object.state_event = 'ignite'
    
    assert_instance_of StateMachine::Transition, @events.attribute_transition_for(@object)
  end
end
