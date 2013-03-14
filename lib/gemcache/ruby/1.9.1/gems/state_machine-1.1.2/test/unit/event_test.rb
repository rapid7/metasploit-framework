require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class EventByDefaultTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    
    @object = @klass.new
  end
  
  def test_should_have_a_machine
    assert_equal @machine, @event.machine
  end
  
  def test_should_have_a_name
    assert_equal :ignite, @event.name
  end
  
  def test_should_have_a_qualified_name
    assert_equal :ignite, @event.qualified_name
  end
  
  def test_should_have_a_human_name
    assert_equal 'ignite', @event.human_name
  end
  
  def test_should_not_have_any_branches
    assert @event.branches.empty?
  end
  
  def test_should_have_no_known_states
    assert @event.known_states.empty?
  end
  
  def test_should_not_be_able_to_fire
    assert !@event.can_fire?(@object)
  end
  
  def test_should_not_have_a_transition
    assert_nil @event.transition_for(@object)
  end
  
  def test_should_define_a_predicate
    assert @object.respond_to?(:can_ignite?)
  end
  
  def test_should_define_a_transition_accessor
    assert @object.respond_to?(:ignite_transition)
  end
  
  def test_should_define_an_action
    assert @object.respond_to?(:ignite)
  end
  
  def test_should_define_a_bang_action
    assert @object.respond_to?(:ignite!)
  end
end

class EventTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @event.transition :parked => :idling
  end
  
  def test_should_allow_changing_machine
    new_machine = StateMachine::Machine.new(Class.new)
    @event.machine = new_machine
    assert_equal new_machine, @event.machine
  end
  
  def test_should_allow_changing_human_name
    @event.human_name = 'Stop'
    assert_equal 'Stop', @event.human_name
  end
  
  def test_should_provide_matcher_helpers_during_initialization
    matchers = []
    
    @event.instance_eval do
      matchers = [all, any, same]
    end
    
    assert_equal [StateMachine::AllMatcher.instance, StateMachine::AllMatcher.instance, StateMachine::LoopbackMatcher.instance], matchers
  end
  
  def test_should_use_pretty_inspect
    assert_match "#<StateMachine::Event name=:ignite transitions=[:parked => :idling]>", @event.inspect
  end
end

class EventWithHumanNameTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite, :human_name => 'start')
  end
  
  def test_should_use_custom_human_name
    assert_equal 'start', @event.human_name
  end
end

class EventWithDynamicHumanNameTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite, :human_name => lambda {|event, object| ['start', object]})
  end
  
  def test_should_use_custom_human_name
    human_name, klass = @event.human_name
    assert_equal 'start', human_name
    assert_equal @klass, klass
  end
  
  def test_should_allow_custom_class_to_be_passed_through
    human_name, klass = @event.human_name(1)
    assert_equal 'start', human_name
    assert_equal 1, klass
  end
  
  def test_should_not_cache_value
    assert_not_same @event.human_name, @event.human_name
  end
end

class EventWithConflictingHelpersBeforeDefinitionTest < Test::Unit::TestCase
  def setup
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    @superclass = Class.new do
      def can_ignite?
        0
      end
      
      def ignite_transition
        0
      end
      
      def ignite
        0
      end
      
      def ignite!
        0
      end
    end
    @klass = Class.new(@superclass)
    @machine = StateMachine::Machine.new(@klass)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @object = @klass.new
  end
  
  def test_should_not_redefine_predicate
    assert_equal 0, @object.can_ignite?
  end
  
  def test_should_not_redefine_transition_accessor
    assert_equal 0, @object.ignite_transition
  end
  
  def test_should_not_redefine_action
    assert_equal 0, @object.ignite
  end
  
  def test_should_not_redefine_bang_action
    assert_equal 0, @object.ignite!
  end
  
  def test_should_output_warning
    expected = %w(can_ignite? ignite_transition ignite ignite!).map do |method|
      "Instance method \"#{method}\" is already defined in #{@superclass.to_s}, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n"
    end.join
    
    assert_equal expected, $stderr.string
  end
  
  def teardown
    $stderr = @original_stderr
  end
end

class EventWithConflictingHelpersAfterDefinitionTest < Test::Unit::TestCase
  def setup
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    @klass = Class.new do
      def can_ignite?
        0
      end
      
      def ignite_transition
        0
      end
      
      def ignite
        0
      end
      
      def ignite!
        0
      end
    end
    @machine = StateMachine::Machine.new(@klass)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @object = @klass.new
  end
  
  def test_should_not_redefine_predicate
    assert_equal 0, @object.can_ignite?
  end
  
  def test_should_not_redefine_transition_accessor
    assert_equal 0, @object.ignite_transition
  end
  
  def test_should_not_redefine_action
    assert_equal 0, @object.ignite
  end
  
  def test_should_not_redefine_bang_action
    assert_equal 0, @object.ignite!
  end
  
  def test_should_allow_super_chaining
    @klass.class_eval do
      def can_ignite?
        super
      end
      
      def ignite_transition
        super
      end
      
      def ignite
        super
      end
      
      def ignite!
        super
      end
    end
    
    assert_equal false, @object.can_ignite?
    assert_equal nil, @object.ignite_transition
    assert_equal false, @object.ignite
    assert_raise(StateMachine::InvalidTransition) { @object.ignite! }
  end
  
  def test_should_not_output_warning
    assert_equal '', $stderr.string
  end
  
  def teardown
    $stderr = @original_stderr
  end
end

class EventWithConflictingMachineTest < Test::Unit::TestCase
  def setup
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    @klass = Class.new
    @state_machine = StateMachine::Machine.new(@klass, :state)
    @state_machine.state :parked, :idling
    @state_machine.events << @state_event = StateMachine::Event.new(@state_machine, :ignite)
  end
  
  def test_should_not_overwrite_first_event
    @status_machine = StateMachine::Machine.new(@klass, :status)
    @status_machine.state :first_gear, :second_gear
    @status_machine.events << @status_event = StateMachine::Event.new(@status_machine, :ignite)
    
    @object = @klass.new
    @object.state = 'parked'
    @object.status = 'first_gear'
    
    @state_event.transition(:parked => :idling)
    @status_event.transition(:parked => :first_gear)
    
    @object.ignite
    assert_equal 'idling', @object.state
    assert_equal 'first_gear', @object.status
  end
  
  def test_should_output_warning
    @status_machine = StateMachine::Machine.new(@klass, :status)
    @status_machine.events << @status_event = StateMachine::Event.new(@status_machine, :ignite)
    
    assert_equal "Event :ignite for :status is already defined in :state\n", $stderr.string
  end
  
  def test_should_not_output_warning_if_using_different_namespace
    @status_machine = StateMachine::Machine.new(@klass, :status, :namespace => 'alarm')
    @status_machine.events << @status_event = StateMachine::Event.new(@status_machine, :ignite)
    
    assert_equal '', $stderr.string
  end
  
  def teardown
    $stderr = @original_stderr
  end
end

class EventWithNamespaceTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :namespace => 'alarm')
    @machine.events << @event = StateMachine::Event.new(@machine, :enable)
    @object = @klass.new
  end
  
  def test_should_have_a_name
    assert_equal :enable, @event.name
  end
  
  def test_should_have_a_qualified_name
    assert_equal :enable_alarm, @event.qualified_name
  end
  
  def test_should_namespace_predicate
    assert @object.respond_to?(:can_enable_alarm?)
  end
  
  def test_should_namespace_transition_accessor
    assert @object.respond_to?(:enable_alarm_transition)
  end
  
  def test_should_namespace_action
    assert @object.respond_to?(:enable_alarm)
  end
  
  def test_should_namespace_bang_action
    assert @object.respond_to?(:enable_alarm!)
  end
end

class EventContextTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite, :human_name => 'start')
  end
  
  def test_should_evaluate_within_the_event
    scope = nil
    @event.context { scope = self }
    assert_equal @event, scope
  end
end

class EventTransitionsTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
  end
  
  def test_should_not_raise_exception_if_implicit_option_specified
    assert_nothing_raised {@event.transition(:invalid => :valid)}
  end
  
  def test_should_not_allow_on_option
    exception = assert_raise(ArgumentError) {@event.transition(:on => :ignite)}
    assert_equal 'Invalid key(s): on', exception.message
  end
  
  def test_should_automatically_set_on_option
    branch = @event.transition(:to => :idling)
    assert_instance_of StateMachine::WhitelistMatcher, branch.event_requirement
    assert_equal [:ignite], branch.event_requirement.values
  end
  
  def test_should_not_allow_except_to_option
    exception = assert_raise(ArgumentError) {@event.transition(:except_to => :parked)}
    assert_equal 'Invalid key(s): except_to', exception.message
  end
  
  def test_should_not_allow_except_on_option
    exception = assert_raise(ArgumentError) {@event.transition(:except_on => :ignite)}
    assert_equal 'Invalid key(s): except_on', exception.message
  end
  
  def test_should_allow_transitioning_without_a_to_state
    assert_nothing_raised {@event.transition(:from => :parked)}
  end
  
  def test_should_allow_transitioning_without_a_from_state
    assert_nothing_raised {@event.transition(:to => :idling)}
  end
  
  def test_should_allow_except_from_option
    assert_nothing_raised {@event.transition(:except_from => :idling)}
  end
  
  def test_should_allow_transitioning_from_a_single_state
    assert @event.transition(:parked => :idling)
  end
  
  def test_should_allow_transitioning_from_multiple_states
    assert @event.transition([:parked, :idling] => :idling)
  end
  
  def test_should_have_transitions
    branch = @event.transition(:to => :idling)
    assert_equal [branch], @event.branches
  end
end

class EventAfterBeingCopiedTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @copied_event = @event.dup
  end
  
  def test_should_not_have_the_same_collection_of_branches
    assert_not_same @event.branches, @copied_event.branches
  end
  
  def test_should_not_have_the_same_collection_of_known_states
    assert_not_same @event.known_states, @copied_event.known_states
  end
end

class EventWithoutTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @object = @klass.new
  end
  
  def test_should_not_be_able_to_fire
    assert !@event.can_fire?(@object)
  end
  
  def test_should_not_have_a_transition
    assert_nil @event.transition_for(@object)
  end
  
  def test_should_not_fire
    assert !@event.fire(@object)
  end
  
  def test_should_not_change_the_current_state
    @event.fire(@object)
    assert_nil @object.state
  end
end

class EventWithTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @event.transition(:parked => :idling)
    @event.transition(:first_gear => :idling)
  end
  
  def test_should_include_all_transition_states_in_known_states
    assert_equal [:parked, :idling, :first_gear], @event.known_states
  end
  
  def test_should_include_new_transition_states_after_calling_known_states
    @event.known_states
    @event.transition(:stalled => :idling)
    
    assert_equal [:parked, :idling, :first_gear, :stalled], @event.known_states
  end
  
  def test_should_clear_known_states_on_reset
    @event.reset
    assert_equal [], @event.known_states
  end
  
  def test_should_use_pretty_inspect
    assert_match "#<StateMachine::Event name=:ignite transitions=[:parked => :idling, :first_gear => :idling]>", @event.inspect
  end
end

class EventWithoutMatchingTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @event.transition(:parked => :idling)
    
    @object = @klass.new
    @object.state = 'idling'
  end
  
  def test_should_not_be_able_to_fire
    assert !@event.can_fire?(@object)
  end
  
  def test_should_be_able_to_fire_with_custom_from_state
    assert @event.can_fire?(@object, :from => :parked)
  end
  
  def test_should_not_have_a_transition
    assert_nil @event.transition_for(@object)
  end
  
  def test_should_have_a_transition_with_custom_from_state
    assert_not_nil @event.transition_for(@object, :from => :parked)
  end
  
  def test_should_not_fire
    assert !@event.fire(@object)
  end
  
  def test_should_not_change_the_current_state
    @event.fire(@object)
    assert_equal 'idling', @object.state
  end
end

class EventWithMatchingDisabledTransitionsTest < Test::Unit::TestCase
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
    end
    
    @machine = StateMachine::Machine.new(@klass, :integration => :custom)
    @machine.state :parked, :idling
    
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @event.transition(:parked => :idling, :if => lambda {false})
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_not_be_able_to_fire
    assert !@event.can_fire?(@object)
  end
  
  def test_should_be_able_to_fire_with_disabled_guards
    assert @event.can_fire?(@object, :guard => false)
  end
  
  def test_should_not_have_a_transition
    assert_nil @event.transition_for(@object)
  end
  
  def test_should_have_a_transition_with_disabled_guards
    assert_not_nil @event.transition_for(@object, :guard => false)
  end
  
  def test_should_not_fire
    assert !@event.fire(@object)
  end
  
  def test_should_not_change_the_current_state
    @event.fire(@object)
    assert_equal 'parked', @object.state
  end
  
  def test_should_invalidate_the_state
    @event.fire(@object)
    assert_equal ['cannot transition via "ignite"'], @object.errors
  end
  
  def test_should_invalidate_with_human_event_name
    @event.human_name = 'start'
    @event.fire(@object)
    assert_equal ['cannot transition via "start"'], @object.errors
  end
  
  def test_should_invalid_with_human_state_name_if_specified
    klass = Class.new do
      attr_accessor :errors
    end
    
    machine = StateMachine::Machine.new(klass, :integration => :custom, :messages => {:invalid_transition => 'cannot transition via "%s" from "%s"'})
    parked, idling = machine.state :parked, :idling
    parked.human_name = 'stopped'
    
    machine.events << event = StateMachine::Event.new(machine, :ignite)
    event.transition(:parked => :idling, :if => lambda {false})
    
    object = @klass.new
    object.state = 'parked'
    
    event.fire(object)
    assert_equal ['cannot transition via "ignite" from "stopped"'], object.errors
  end
  
  def test_should_reset_existing_error
    @object.errors = ['invalid']
    
    @event.fire(@object)
    assert_equal ['cannot transition via "ignite"'], @object.errors
  end
  
  def test_should_run_failure_callbacks
    callback_args = nil
    @machine.after_failure {|*args| callback_args = args}
    
    @event.fire(@object)
    
    object, transition = callback_args
    assert_equal @object, object
    assert_not_nil transition
    assert_equal @object, transition.object
    assert_equal @machine, transition.machine
    assert_equal :ignite, transition.event
    assert_equal :parked, transition.from_name
    assert_equal :parked, transition.to_name
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class EventWithMatchingEnabledTransitionsTest < Test::Unit::TestCase
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
    end
    
    @machine = StateMachine::Machine.new(@klass, :integration => :custom)
    @machine.state :parked, :idling
    
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @event.transition(:parked => :idling)
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_be_able_to_fire
    assert @event.can_fire?(@object)
  end
  
  def test_should_have_a_transition
    transition = @event.transition_for(@object)
    assert_not_nil transition
    assert_equal 'parked', transition.from
    assert_equal 'idling', transition.to
    assert_equal :ignite, transition.event
  end
  
  def test_should_fire
    assert @event.fire(@object)
  end
  
  def test_should_change_the_current_state
    @event.fire(@object)
    assert_equal 'idling', @object.state
  end
  
  def test_should_reset_existing_error
    @object.errors = ['invalid']
    
    @event.fire(@object)
    assert_equal [], @object.errors
  end
  
  def test_should_not_invalidate_the_state
    @event.fire(@object)
    assert_equal [], @object.errors
  end
  
  def test_should_not_be_able_to_fire_on_reset
    @event.reset
    assert !@event.can_fire?(@object)
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class EventWithTransitionWithoutToStateTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked
    
    @machine.events << @event = StateMachine::Event.new(@machine, :park)
    @event.transition(:from => :parked)
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_be_able_to_fire
    assert @event.can_fire?(@object)
  end
  
  def test_should_have_a_transition
    transition = @event.transition_for(@object)
    assert_not_nil transition
    assert_equal 'parked', transition.from
    assert_equal 'parked', transition.to
    assert_equal :park, transition.event
  end
  
  def test_should_fire
    assert @event.fire(@object)
  end
  
  def test_should_not_change_the_current_state
    @event.fire(@object)
    assert_equal 'parked', @object.state
  end
end

class EventWithTransitionWithNilToStateTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state nil, :idling
    
    @machine.events << @event = StateMachine::Event.new(@machine, :park)
    @event.transition(:idling => nil)
    
    @object = @klass.new
    @object.state = 'idling'
  end
  
  def test_should_be_able_to_fire
    assert @event.can_fire?(@object)
  end
  
  def test_should_have_a_transition
    transition = @event.transition_for(@object)
    assert_not_nil transition
    assert_equal 'idling', transition.from
    assert_equal nil, transition.to
    assert_equal :park, transition.event
  end
  
  def test_should_fire
    assert @event.fire(@object)
  end
  
  def test_should_not_change_the_current_state
    @event.fire(@object)
    assert_equal nil, @object.state
  end
end

class EventWithMultipleTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @event.transition(:idling => :idling)
    @event.transition(:parked => :idling) # This one should get used
    @event.transition(:parked => :parked)
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_be_able_to_fire
    assert @event.can_fire?(@object)
  end
  
  def test_should_have_a_transition
    transition = @event.transition_for(@object)
    assert_not_nil transition
    assert_equal 'parked', transition.from
    assert_equal 'idling', transition.to
    assert_equal :ignite, transition.event
  end
  
  def test_should_allow_specific_transition_selection_using_from
    transition = @event.transition_for(@object, :from => :idling)
    
    assert_not_nil transition
    assert_equal 'idling', transition.from
    assert_equal 'idling', transition.to
    assert_equal :ignite, transition.event
  end
  
  def test_should_allow_specific_transition_selection_using_to
    transition = @event.transition_for(@object, :from => :parked, :to => :parked)
    
    assert_not_nil transition
    assert_equal 'parked', transition.from
    assert_equal 'parked', transition.to
    assert_equal :ignite, transition.event
  end
  
  def test_should_not_allow_specific_transition_selection_using_on
    exception = assert_raise(ArgumentError) { @event.transition_for(@object, :on => :park) }
    assert_equal 'Invalid key(s): on', exception.message
  end
  
  def test_should_fire
    assert @event.fire(@object)
  end
  
  def test_should_change_the_current_state
    @event.fire(@object)
    assert_equal 'idling', @object.state
  end
end

class EventWithMachineActionTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :saved
      
      def save
        @saved = true
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @machine.state :parked, :idling
    
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @event.transition(:parked => :idling)
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_run_action_on_fire
    @event.fire(@object)
    assert @object.saved
  end
  
  def test_should_not_run_action_if_configured_to_skip
    @event.fire(@object, false)
    assert !@object.saved
  end
end

class EventWithInvalidCurrentStateTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @event.transition(:parked => :idling)
    
    @object = @klass.new
    @object.state = 'invalid'
  end
  
  def test_should_raise_exception_when_checking_availability
    exception = assert_raise(ArgumentError) { @event.can_fire?(@object) }
    assert_equal '"invalid" is not a known state value', exception.message
  end
  
  def test_should_raise_exception_when_finding_transition
    exception = assert_raise(ArgumentError) { @event.transition_for(@object) }
    assert_equal '"invalid" is not a known state value', exception.message
  end
  
  def test_should_raise_exception_when_firing
    exception = assert_raise(ArgumentError) { @event.fire(@object) }
    assert_equal '"invalid" is not a known state value', exception.message
  end
end

class EventOnFailureTest < Test::Unit::TestCase
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
    end
    
    @machine = StateMachine::Machine.new(@klass, :integration => :custom)
    @machine.state :parked
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_invalidate_the_state
    @event.fire(@object)
    assert_equal ['cannot transition via "ignite"'], @object.errors
  end
  
  def test_should_run_failure_callbacks
    callback_args = nil
    @machine.after_failure {|*args| callback_args = args}
    
    @event.fire(@object)
    
    object, transition = callback_args
    assert_equal @object, object
    assert_not_nil transition
    assert_equal @object, transition.object
    assert_equal @machine, transition.machine
    assert_equal :ignite, transition.event
    assert_equal :parked, transition.from_name
    assert_equal :parked, transition.to_name
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class EventWithMarshallingTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def save
        true
      end
    end
    self.class.const_set('Example', @klass)
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @machine.state :parked, :idling
    
    @machine.events << @event = StateMachine::Event.new(@machine, :ignite)
    @event.transition(:parked => :idling)
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_marshal_during_before_callbacks
    @machine.before_transition {|object, transition| Marshal.dump(object)}
    assert_nothing_raised { @event.fire(@object) }
  end
  
  def test_should_marshal_during_action
    @klass.class_eval do
      def save
        Marshal.dump(self)
      end
    end
    
    assert_nothing_raised { @event.fire(@object) }
  end
  
  def test_should_marshal_during_after_callbacks
    @machine.after_transition {|object, transition| Marshal.dump(object)}
    assert_nothing_raised { @event.fire(@object) }
  end
  
  def teardown
    self.class.send(:remove_const, 'Example')
  end
end

begin
  # Load library
  require 'graphviz'
  
  class EventDrawingTest < Test::Unit::TestCase
    def setup
      states = [:parked, :idling, :first_gear]
      
      @machine = StateMachine::Machine.new(Class.new, :initial => :parked)
      @machine.other_states(*states)
      
      graph = GraphViz.new('G')
      states.each {|state| graph.add_node(state.to_s)}
      
      @machine.events << @event = StateMachine::Event.new(@machine , :park)
      @event.transition :parked => :idling
      @event.transition :first_gear => :parked
      @event.transition :except_from => :parked, :to => :parked
      
      @edges = @event.draw(graph)
    end
    
    def test_should_generate_edges_for_each_transition
      assert_equal 4, @edges.size
    end
    
    def test_should_use_event_name_for_edge_label
      assert_equal 'park', @edges.first['label'].to_s.gsub('"', '')
    end
  end
  
  class EventDrawingWithHumanNameTest < Test::Unit::TestCase
    def setup
      states = [:parked, :idling]
      
      @machine = StateMachine::Machine.new(Class.new, :initial => :parked)
      @machine.other_states(*states)
      
      graph = GraphViz.new('G')
      states.each {|state| graph.add_node(state.to_s)}
      
      @machine.events << @event = StateMachine::Event.new(@machine , :park, :human_name => 'Park')
      @event.transition :parked => :idling
      
      @edges = @event.draw(graph, :human_name => true)
    end
    
    def test_should_use_event_human_name_for_edge_label
      assert_equal 'Park', @edges.first['label'].to_s.gsub('"', '')
    end
  end
rescue LoadError
  $stderr.puts 'Skipping GraphViz StateMachine::Event tests. `gem install ruby-graphviz` >= v0.9.0 and try again.'
end unless ENV['TRAVIS']
