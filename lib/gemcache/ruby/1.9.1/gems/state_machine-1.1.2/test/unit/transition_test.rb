require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class TransitionTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_have_an_object
    assert_equal @object, @transition.object
  end
  
  def test_should_have_a_machine
    assert_equal @machine, @transition.machine
  end
  
  def test_should_have_an_event
    assert_equal :ignite, @transition.event
  end
  
  def test_should_have_a_qualified_event
    assert_equal :ignite, @transition.qualified_event
  end
  
  def test_should_have_a_human_event
    assert_equal 'ignite', @transition.human_event
  end
  
  def test_should_have_a_from_value
    assert_equal 'parked', @transition.from
  end
  
  def test_should_have_a_from_name
    assert_equal :parked, @transition.from_name
  end
  
  def test_should_have_a_qualified_from_name
    assert_equal :parked, @transition.qualified_from_name
  end
  
  def test_should_have_a_human_from_name
    assert_equal 'parked', @transition.human_from_name
  end
  
  def test_should_have_a_to_value
    assert_equal 'idling', @transition.to
  end
  
  def test_should_have_a_to_name
    assert_equal :idling, @transition.to_name
  end
  
  def test_should_have_a_qualified_to_name
    assert_equal :idling, @transition.qualified_to_name
  end
  
  def test_should_have_a_human_to_name
    assert_equal 'idling', @transition.human_to_name
  end
  
  def test_should_have_an_attribute
    assert_equal :state, @transition.attribute
  end
  
  def test_should_not_have_an_action
    assert_nil @transition.action
  end
  
  def test_should_not_be_transient
    assert_equal false, @transition.transient?
  end
  
  def test_should_generate_attributes
    expected = {:object => @object, :attribute => :state, :event => :ignite, :from => 'parked', :to => 'idling'}
    assert_equal expected, @transition.attributes
  end
  
  def test_should_have_empty_args
    assert_equal [], @transition.args
  end
  
  def test_should_not_have_a_result
    assert_nil @transition.result
  end
  
  def test_should_use_pretty_inspect
    assert_equal '#<StateMachine::Transition attribute=:state event=:ignite from="parked" from_name=:parked to="idling" to_name=:idling>', @transition.inspect
  end
end

class TransitionWithInvalidNodesTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_raise_exception_without_event
    assert_raise(IndexError) { StateMachine::Transition.new(@object, @machine, nil, :parked, :idling) }
  end
  
  def test_should_raise_exception_with_invalid_event
    assert_raise(IndexError) { StateMachine::Transition.new(@object, @machine, :invalid, :parked, :idling) }
  end
  
  def test_should_raise_exception_with_invalid_from_state
    assert_raise(IndexError) { StateMachine::Transition.new(@object, @machine, :ignite, :invalid, :idling) }
  end
  
  def test_should_raise_exception_with_invalid_to_state
    assert_raise(IndexError) { StateMachine::Transition.new(@object, @machine, :ignite, :parked, :invalid) }
  end
end

class TransitionWithDynamicToValueTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked
    @machine.state :idling, :value => lambda {1}
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_evaluate_to_value
    assert_equal 1, @transition.to
  end
end

class TransitionLoopbackTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked
    @machine.event :park
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :park, :parked, :parked)
  end
  
  def test_should_be_loopback
    assert @transition.loopback?
  end
end

class TransitionWithDifferentStatesTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_not_be_loopback
    assert !@transition.loopback?
  end
end

class TransitionWithNamespaceTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :namespace => 'alarm')
    @machine.state :off, :active
    @machine.event :activate
    
    @object = @klass.new
    @object.state = 'off'
    
    @transition = StateMachine::Transition.new(@object, @machine, :activate, :off, :active)
  end
  
  def test_should_have_an_event
    assert_equal :activate, @transition.event
  end
  
  def test_should_have_a_qualified_event
    assert_equal :activate_alarm, @transition.qualified_event
  end
  
  def test_should_have_a_from_name
    assert_equal :off, @transition.from_name
  end
  
  def test_should_have_a_qualified_from_name
    assert_equal :alarm_off, @transition.qualified_from_name
  end
  
  def test_should_have_a_human_from_name
    assert_equal 'off', @transition.human_from_name
  end
  
  def test_should_have_a_to_name
    assert_equal :active, @transition.to_name
  end
  
  def test_should_have_a_qualified_to_name
    assert_equal :alarm_active, @transition.qualified_to_name
  end
  
  def test_should_have_a_human_to_name
    assert_equal 'active', @transition.human_to_name
  end
end

class TransitionWithCustomMachineAttributeTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :state, :attribute => :state_id)
    @machine.state :off, :value => 1
    @machine.state :active, :value => 2
    @machine.event :activate
    
    @object = @klass.new
    @object.state_id = 1
    
    @transition = StateMachine::Transition.new(@object, @machine, :activate, :off, :active)
  end
  
  def test_should_persist
    @transition.persist
    assert_equal 2, @object.state_id
  end
  
  def test_should_rollback
    @object.state_id = 2
    @transition.rollback
    
    assert_equal 1, @object.state_id
  end
end

class TransitionWithoutReadingStateTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'idling'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling, false)
  end
  
  def test_should_not_read_from_value_from_object
    assert_equal 'parked', @transition.from
  end
  
  def test_should_have_to_value
    assert_equal 'idling', @transition.to
  end
end

class TransitionWithActionTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def save
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_have_an_action
    assert_equal :save, @transition.action
  end
  
  def test_should_not_have_a_result
    assert_nil @transition.result
  end
end

class TransitionAfterBeingPersistedTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    @transition.persist
  end
  
  def test_should_update_state_value
    assert_equal 'idling', @object.state
  end
  
  def test_should_not_change_from_state
    assert_equal 'parked', @transition.from
  end
  
  def test_should_not_change_to_state
    assert_equal 'idling', @transition.to
  end
  
  def test_should_not_be_able_to_persist_twice
    @object.state = 'parked'
    @transition.persist
    assert_equal 'parked', @object.state
  end
  
  def test_should_be_able_to_persist_again_after_resetting
    @object.state = 'parked'
    @transition.reset
    @transition.persist
    assert_equal 'idling', @object.state
  end
  
  def test_should_revert_to_from_state_on_rollback
    @transition.rollback
    assert_equal 'parked', @object.state
  end
end

class TransitionAfterBeingRolledBackTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    @object.state = 'idling'
    
    @transition.rollback
  end
  
  def test_should_update_state_value_to_from_state
    assert_equal 'parked', @object.state
  end
  
  def test_should_not_change_from_state
    assert_equal 'parked', @transition.from
  end
  
  def test_should_not_change_to_state
    assert_equal 'idling', @transition.to
  end
  
  def test_should_still_be_able_to_persist
    @transition.persist
    assert_equal 'idling', @object.state
  end
end

class TransitionWithoutCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_succeed
    assert_equal true, @transition.run_callbacks
  end
  
  def test_should_succeed_if_after_callbacks_skipped
    assert_equal true, @transition.run_callbacks(:after => false)
  end
  
  def test_should_call_block_if_provided
    @transition.run_callbacks { @ran_block = true; {} }
    assert @ran_block
  end
  
  def test_should_track_block_result
    @transition.run_callbacks {{:result => 1}}
    assert_equal 1, @transition.result
  end
end

class TransitionWithBeforeCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_run_before_callbacks
    @machine.before_transition {@run = true}
    result = @transition.run_callbacks
    
    assert_equal true, result
    assert_equal true, @run
  end
  
  def test_should_only_run_those_that_match_transition_context
    @count = 0
    callback = lambda {@count += 1}
    
    @machine.before_transition :from => :parked, :to => :idling, :on => :park, :do => callback
    @machine.before_transition :from => :parked, :to => :parked, :on => :park, :do => callback
    @machine.before_transition :from => :parked, :to => :idling, :on => :ignite, :do => callback
    @machine.before_transition :from => :idling, :to => :idling, :on => :park, :do => callback
    @transition.run_callbacks
    
    assert_equal 1, @count
  end
  
  def test_should_pass_transition_as_argument
    @machine.before_transition {|*args| @args = args}
    @transition.run_callbacks
    
    assert_equal [@object, @transition], @args
  end
  
  def test_should_catch_halts
    @machine.before_transition {throw :halt}
    
    result = nil
    assert_nothing_thrown { result = @transition.run_callbacks }
    assert_equal false, result
  end
  
  def test_should_not_catch_exceptions
    @machine.before_transition {raise ArgumentError}
    assert_raise(ArgumentError) { @transition.run_callbacks }
  end
  
  def test_should_not_be_able_to_run_twice
    @count = 0
    @machine.before_transition {@count += 1}
    @transition.run_callbacks
    @transition.run_callbacks
    assert_equal 1, @count
  end
  
  def test_should_be_able_to_run_again_after_halt
    @count = 0
    @machine.before_transition {@count += 1; throw :halt}
    @transition.run_callbacks
    @transition.run_callbacks
    assert_equal 2, @count
  end
  
  def test_should_be_able_to_run_again_after_resetting
    @count = 0
    @machine.before_transition {@count += 1}
    @transition.run_callbacks
    @transition.reset
    @transition.run_callbacks
    assert_equal 2, @count
  end
  
  def test_should_succeed_if_block_result_is_false
    @machine.before_transition {@run = true}
    assert_equal true, @transition.run_callbacks {{:result => false}}
    assert @run
  end
  
  def test_should_succeed_if_block_result_is_true
    @machine.before_transition {@run = true}
    assert_equal true, @transition.run_callbacks {{:result => true}}
    assert @run
  end
  
  def test_should_succeed_if_block_success_is_false
    @machine.before_transition {@run = true}
    assert_equal true, @transition.run_callbacks {{:success => false}}
    assert @run
  end
  
  def test_should_succeed_if_block_success_is_false
    @machine.before_transition {@run = true}
    assert_equal true, @transition.run_callbacks {{:success => true}}
    assert @run
  end
end

class TransitionWithMultipleBeforeCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_run_in_the_order_they_were_defined
    @callbacks = []
    @machine.before_transition {@callbacks << 1}
    @machine.before_transition {@callbacks << 2}
    @transition.run_callbacks
    
    assert_equal [1, 2], @callbacks
  end
  
  def test_should_not_run_further_callbacks_if_halted
    @callbacks = []
    @machine.before_transition {@callbacks << 1; throw :halt}
    @machine.before_transition {@callbacks << 2}
    
    assert_equal false, @transition.run_callbacks
    assert_equal [1], @callbacks
  end
  
  def test_should_fail_if_any_callback_halted
    @machine.before_transition {true}
    @machine.before_transition {throw :halt}
    
    assert_equal false, @transition.run_callbacks
  end
end

class TransitionWithAfterCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_run_after_callbacks
    @machine.after_transition {|object| @run = true}
    result = @transition.run_callbacks
    
    assert_equal true, result
    assert_equal true, @run
  end
  
  def test_should_only_run_those_that_match_transition_context
    @count = 0
    callback = lambda {@count += 1}
    
    @machine.after_transition :from => :parked, :to => :idling, :on => :park, :do => callback
    @machine.after_transition :from => :parked, :to => :parked, :on => :park, :do => callback
    @machine.after_transition :from => :parked, :to => :idling, :on => :ignite, :do => callback
    @machine.after_transition :from => :idling, :to => :idling, :on => :park, :do => callback
    @transition.run_callbacks
    
    assert_equal 1, @count
  end
  
  def test_should_not_run_if_not_successful
    @machine.after_transition {|object| @run = true}
    @transition.run_callbacks {{:success => false}}
    assert !@run
  end
  
  def test_should_run_if_successful
    @machine.after_transition {|object| @run = true}
    @transition.run_callbacks {{:success => true}}
    assert @run
  end
  
  def test_should_pass_transition_as_argument
    @machine.after_transition {|*args| @args = args}
    
    @transition.run_callbacks
    assert_equal [@object, @transition], @args
  end
  
  def test_should_catch_halts
    @machine.after_transition {throw :halt}
    
    result = nil
    assert_nothing_thrown { result = @transition.run_callbacks }
    assert_equal true, result
  end
  
  def test_should_not_catch_exceptions
    @machine.after_transition {raise ArgumentError}
    assert_raise(ArgumentError) { @transition.run_callbacks }
  end
  
  def test_should_not_be_able_to_run_twice
    @count = 0
    @machine.after_transition {@count += 1}
    @transition.run_callbacks
    @transition.run_callbacks
    assert_equal 1, @count
  end
  
  def test_should_not_be_able_to_run_twice_if_halted
    @count = 0
    @machine.after_transition {@count += 1; throw :halt}
    @transition.run_callbacks
    @transition.run_callbacks
    assert_equal 1, @count
  end
  
  def test_should_be_able_to_run_again_after_resetting
    @count = 0
    @machine.after_transition {@count += 1}
    @transition.run_callbacks
    @transition.reset
    @transition.run_callbacks
    assert_equal 2, @count
  end
end

class TransitionWithMultipleAfterCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_run_in_the_order_they_were_defined
    @callbacks = []
    @machine.after_transition {@callbacks << 1}
    @machine.after_transition {@callbacks << 2}
    @transition.run_callbacks
    
    assert_equal [1, 2], @callbacks
  end
  
  def test_should_not_run_further_callbacks_if_halted
    @callbacks = []
    @machine.after_transition {@callbacks << 1; throw :halt}
    @machine.after_transition {@callbacks << 2}
    
    assert_equal true, @transition.run_callbacks
    assert_equal [1], @callbacks
  end
  
  def test_should_fail_if_any_callback_halted
    @machine.after_transition {true}
    @machine.after_transition {throw :halt}
    
    assert_equal true, @transition.run_callbacks
  end
end

class TransitionWithAroundCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_run_around_callbacks
    @machine.around_transition {|object, transition, block| @run_before = true; block.call; @run_after = true}
    result = @transition.run_callbacks
    
    assert_equal true, result
    assert_equal true, @run_before
    assert_equal true, @run_after
  end
  
  def test_should_only_run_those_that_match_transition_context
    @count = 0
    callback = lambda {|object, transition, block| @count += 1; block.call}
    
    @machine.around_transition :from => :parked, :to => :idling, :on => :park, :do => callback
    @machine.around_transition :from => :parked, :to => :parked, :on => :park, :do => callback
    @machine.around_transition :from => :parked, :to => :idling, :on => :ignite, :do => callback
    @machine.around_transition :from => :idling, :to => :idling, :on => :park, :do => callback
    @transition.run_callbacks
    
    assert_equal 1, @count
  end
  
  def test_should_pass_transition_as_argument
    @machine.around_transition {|*args| block = args.pop; @args = args; block.call}
    @transition.run_callbacks
    
    assert_equal [@object, @transition], @args
  end
  
  def test_should_run_block_between_callback
    @callbacks = []
    @machine.around_transition {|block| @callbacks << :before; block.call; @callbacks << :after}
    @transition.run_callbacks { @callbacks << :within; {:success => true} }
    
    assert_equal [:before, :within, :after], @callbacks
  end
  
  def test_should_have_access_to_result_after_yield
    @machine.around_transition {|block| @before_result = @transition.result; block.call; @after_result = @transition.result}
    @transition.run_callbacks {{:result => 1, :success => true}}
    
    assert_nil @before_result
    assert_equal 1, @after_result
  end
  
  def test_should_catch_before_yield_halts
    @machine.around_transition {throw :halt}
    
    result = nil
    assert_nothing_thrown { result = @transition.run_callbacks }
    assert_equal false, result
  end
  
  def test_should_catch_after_yield_halts
    @machine.around_transition {|block| block.call; throw :halt}
    
    result = nil
    assert_nothing_thrown { result = @transition.run_callbacks }
    assert_equal true, result
  end
  
  def test_should_not_catch_before_yield
    @machine.around_transition {raise ArgumentError}
    assert_raise(ArgumentError) { @transition.run_callbacks }
  end
  
  def test_should_not_catch_after_yield
    @machine.around_transition {|block| block.call; raise ArgumentError}
    assert_raise(ArgumentError) { @transition.run_callbacks }
  end
  
  def test_should_fail_if_not_yielded
    @machine.around_transition {}
    
    result = nil
    assert_nothing_thrown { result = @transition.run_callbacks }
    assert_equal false, result
  end
  
  def test_should_not_be_able_to_run_twice
    @before_count = 0
    @after_count = 0
    @machine.around_transition {|block| @before_count += 1; block.call; @after_count += 1}
    @transition.run_callbacks
    @transition.run_callbacks
    assert_equal 1, @before_count
    assert_equal 1, @after_count
  end
  
  def test_should_be_able_to_run_again_after_resetting
    @before_count = 0
    @after_count = 0
    @machine.around_transition {|block| @before_count += 1; block.call; @after_count += 1}
    @transition.run_callbacks
    @transition.reset
    @transition.run_callbacks
    assert_equal 2, @before_count
    assert_equal 2, @after_count
  end
  
  def test_should_succeed_if_block_result_is_false
    @machine.around_transition {|block| @before_run = true; block.call; @after_run = true}
    assert_equal true, @transition.run_callbacks {{:success => true, :result => false}}
    assert @before_run
    assert @after_run
  end
  
  def test_should_succeed_if_block_result_is_true
    @machine.around_transition {|block| @before_run = true; block.call; @after_run = true}
    assert_equal true, @transition.run_callbacks {{:success => true, :result => true}}
    assert @before_run
    assert @after_run
  end
  
  def test_should_only_run_before_if_block_success_is_false
    @machine.around_transition {|block| @before_run = true; block.call; @after_run = true}
    assert_equal true, @transition.run_callbacks {{:success => false}}
    assert @before_run
    assert !@after_run
  end
  
  def test_should_succeed_if_block_success_is_false
    @machine.around_transition {|block| @before_run = true; block.call; @after_run = true}
    assert_equal true, @transition.run_callbacks {{:success => true}}
    assert @before_run
    assert @after_run
  end
end

class TransitionWithMultipleAroundCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_before_yield_in_the_order_they_were_defined
    @callbacks = []
    @machine.around_transition {|block| @callbacks << 1; block.call}
    @machine.around_transition {|block| @callbacks << 2; block.call}
    @transition.run_callbacks
    
    assert_equal [1, 2], @callbacks
  end
  
  def test_should_before_yield_multiple_methods_in_the_order_they_were_defined
    @callbacks = []
    @machine.around_transition(lambda {|block| @callbacks << 1; block.call}, lambda {|block| @callbacks << 2; block.call})
    @machine.around_transition(lambda {|block| @callbacks << 3; block.call}, lambda {|block| @callbacks << 4; block.call})
    @transition.run_callbacks
    
    assert_equal [1, 2, 3, 4], @callbacks
  end
  
  def test_should_after_yield_in_the_reverse_order_they_were_defined
    @callbacks = []
    @machine.around_transition {|block| block.call; @callbacks << 1}
    @machine.around_transition {|block| block.call; @callbacks << 2}
    @transition.run_callbacks
    
    assert_equal [2, 1], @callbacks
  end
  
  def test_should_after_yield_multiple_methods_in_the_reverse_order_they_were_defined
    @callbacks = []
    @machine.around_transition(lambda {|block| block.call; @callbacks << 1}) {|block| block.call; @callbacks << 2}
    @machine.around_transition(lambda {|block| block.call; @callbacks << 3}) {|block| block.call; @callbacks << 4}
    @transition.run_callbacks
    
    assert_equal [4, 3, 2, 1], @callbacks
  end
  
  def test_should_run_block_between_callback
    @callbacks = []
    @machine.around_transition {|block| @callbacks << :before_1; block.call; @callbacks << :after_1}
    @machine.around_transition {|block| @callbacks << :before_2; block.call; @callbacks << :after_2}
    @transition.run_callbacks { @callbacks << :within; {:success => true} }
    
    assert_equal [:before_1, :before_2, :within, :after_2, :after_1], @callbacks
  end
  
  def test_should_have_access_to_result_after_yield
    @machine.around_transition {|block| @before_result_1 = @transition.result; block.call; @after_result_1 = @transition.result}
    @machine.around_transition {|block| @before_result_2 = @transition.result; block.call; @after_result_2 = @transition.result}
    @transition.run_callbacks {{:result => 1, :success => true}}
    
    assert_nil @before_result_1
    assert_nil @before_result_2
    assert_equal 1, @after_result_1
    assert_equal 1, @after_result_2
  end
  
  def test_should_fail_if_any_before_yield_halted
    @machine.around_transition {|block| block.call}
    @machine.around_transition {throw :halt}
    
    assert_equal false, @transition.run_callbacks
  end
  
  def test_should_not_continue_around_callbacks_if_before_yield_halted
    @callbacks = []
    @machine.around_transition {@callbacks << 1; throw :halt}
    @machine.around_transition {|block| @callbacks << 2; block.call; @callbacks << 3}
    
    assert_equal false, @transition.run_callbacks
    assert_equal [1], @callbacks
  end
  
  def test_should_not_continue_around_callbacks_if_later_before_yield_halted
    @callbacks = []
    @machine.around_transition {|block| block.call; @callbacks << 1}
    @machine.around_transition {throw :halt}
    
    @transition.run_callbacks
    assert_equal [], @callbacks
  end
  
  def test_should_not_run_further_callbacks_if_after_yield_halted
    @callbacks = []
    @machine.around_transition {|block| block.call; @callbacks << 1}
    @machine.around_transition {|block| block.call; throw :halt}
    
    assert_equal true, @transition.run_callbacks
    assert_equal [], @callbacks
  end
  
  def test_should_fail_if_any_fail_to_yield
    @callbacks = []
    @machine.around_transition {@callbacks << 1}
    @machine.around_transition {|block| @callbacks << 2; block.call; @callbacks << 3}
    
    assert_equal false, @transition.run_callbacks
    assert_equal [1], @callbacks
  end
end

class TransitionWithFailureCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_only_run_those_that_match_transition_context
    @count = 0
    callback = lambda {@count += 1}
    
    @machine.after_failure :do => callback
    @machine.after_failure :on => :park, :do => callback
    @machine.after_failure :on => :ignite, :do => callback
    @transition.run_callbacks {{:success => false}}
    
    assert_equal 2, @count
  end
  
  def test_should_run_if_not_successful
    @machine.after_failure {|object| @run = true}
    @transition.run_callbacks {{:success => false}}
    assert @run
  end
  
  def test_should_not_run_if_successful
    @machine.after_failure {|object| @run = true}
    @transition.run_callbacks {{:success => true}}
    assert !@run
  end
  
  def test_should_pass_transition_as_argument
    @machine.after_failure {|*args| @args = args}
    
    @transition.run_callbacks {{:success => false}}
    assert_equal [@object, @transition], @args
  end
  
  def test_should_catch_halts
    @machine.after_failure {throw :halt}
    
    result = nil
    assert_nothing_thrown { result = @transition.run_callbacks {{:success => false}} }
    assert_equal true, result
  end
  
  def test_should_not_catch_exceptions
    @machine.after_failure {raise ArgumentError}
    assert_raise(ArgumentError) { @transition.run_callbacks {{:success => false}} }
  end
  
  def test_should_not_be_able_to_run_twice
    @count = 0
    @machine.after_failure {@count += 1}
    @transition.run_callbacks {{:success => false}}
    @transition.run_callbacks {{:success => false}}
    assert_equal 1, @count
  end
  
  def test_should_not_be_able_to_run_twice_if_halted
    @count = 0
    @machine.after_failure {@count += 1; throw :halt}
    @transition.run_callbacks {{:success => false}}
    @transition.run_callbacks {{:success => false}}
    assert_equal 1, @count
  end
  
  def test_should_be_able_to_run_again_after_resetting
    @count = 0
    @machine.after_failure {@count += 1}
    @transition.run_callbacks {{:success => false}}
    @transition.reset
    @transition.run_callbacks {{:success => false}}
    assert_equal 2, @count
  end
end

class TransitionWithMultipleFailureCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_run_in_the_order_they_were_defined
    @callbacks = []
    @machine.after_failure {@callbacks << 1}
    @machine.after_failure {@callbacks << 2}
    @transition.run_callbacks {{:success => false}}
    
    assert_equal [1, 2], @callbacks
  end
  
  def test_should_not_run_further_callbacks_if_halted
    @callbacks = []
    @machine.after_failure {@callbacks << 1; throw :halt}
    @machine.after_failure {@callbacks << 2}
    
    assert_equal true, @transition.run_callbacks {{:success => false}}
    assert_equal [1], @callbacks
  end
  
  def test_should_fail_if_any_callback_halted
    @machine.after_failure {true}
    @machine.after_failure {throw :halt}
    
    assert_equal true, @transition.run_callbacks {{:success => false}}
  end
end

class TransitionWithMixedCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_before_and_around_callbacks_in_order_defined
    @callbacks = []
    @machine.before_transition {@callbacks << :before_1}
    @machine.around_transition {|block| @callbacks << :around; block.call}
    @machine.before_transition {@callbacks << :before_2}
    
    assert_equal true, @transition.run_callbacks
    assert_equal [:before_1, :around, :before_2], @callbacks
  end
  
  def test_should_run_around_callbacks_before_after_callbacks
    @callbacks = []
    @machine.after_transition {@callbacks << :after_1}
    @machine.around_transition {|block| block.call; @callbacks << :after_2}
    @machine.after_transition {@callbacks << :after_3}
    
    assert_equal true, @transition.run_callbacks
    assert_equal [:after_2, :after_1, :after_3], @callbacks
  end
  
  def test_should_have_access_to_result_for_both_after_and_around_callbacks
    @machine.after_transition {@after_result = @transition.result}
    @machine.around_transition {|block| block.call; @around_result = @transition.result}
    
    @transition.run_callbacks {{:result => 1, :success => true}}
    assert_equal 1, @after_result
    assert_equal 1, @around_result
  end
  
  def test_should_not_run_further_callbacks_if_before_callback_halts
    @callbacks = []
    @machine.before_transition {@callbacks << :before_1}
    @machine.around_transition {|block| @callbacks << :before_around_1; block.call; @callbacks << :after_around_1}
    @machine.before_transition {@callbacks << :before_2; throw :halt}
    @machine.around_transition {|block| @callbacks << :before_around_2; block.call; @callbacks << :after_around_2}
    @machine.after_transition {@callbacks << :after}
    
    assert_equal false, @transition.run_callbacks
    assert_equal [:before_1, :before_around_1, :before_2], @callbacks
  end
  
  def test_should_not_run_further_callbacks_if_before_yield_halts
    @callbacks = []
    @machine.before_transition {@callbacks << :before_1}
    @machine.around_transition {|block| @callbacks << :before_around_1; throw :halt}
    @machine.before_transition {@callbacks << :before_2; throw :halt}
    @machine.around_transition {|block| @callbacks << :before_around_2; block.call; @callbacks << :after_around_2}
    @machine.after_transition {@callbacks << :after}
    
    assert_equal false, @transition.run_callbacks
    assert_equal [:before_1, :before_around_1], @callbacks
  end
  
  def test_should_not_run_further_callbacks_if_around_callback_fails_to_yield
    @callbacks = []
    @machine.before_transition {@callbacks << :before_1}
    @machine.around_transition {|block| @callbacks << :before_around_1}
    @machine.before_transition {@callbacks << :before_2; throw :halt}
    @machine.around_transition {|block| @callbacks << :before_around_2; block.call; @callbacks << :after_around_2}
    @machine.after_transition {@callbacks << :after}
    
    assert_equal false, @transition.run_callbacks
    assert_equal [:before_1, :before_around_1], @callbacks
  end
  
  def test_should_not_run_further_callbacks_if_after_yield_halts
    @callbacks = []
    @machine.before_transition {@callbacks << :before_1}
    @machine.around_transition {|block| @callbacks << :before_around_1; block.call; @callbacks << :after_around_1; throw :halt}
    @machine.before_transition {@callbacks << :before_2}
    @machine.around_transition {|block| @callbacks << :before_around_2; block.call; @callbacks << :after_around_2}
    @machine.after_transition {@callbacks << :after}
    
    assert_equal true, @transition.run_callbacks
    assert_equal [:before_1, :before_around_1, :before_2, :before_around_2, :after_around_2, :after_around_1], @callbacks
  end
  
  def test_should_not_run_further_callbacks_if_after_callback_halts
    @callbacks = []
    @machine.before_transition {@callbacks << :before_1}
    @machine.around_transition {|block| @callbacks << :before_around_1; block.call; @callbacks << :after_around_1}
    @machine.before_transition {@callbacks << :before_2}
    @machine.around_transition {|block| @callbacks << :before_around_2; block.call; @callbacks << :after_around_2}
    @machine.after_transition {@callbacks << :after_1; throw :halt}
    @machine.after_transition {@callbacks << :after_2}
    
    assert_equal true, @transition.run_callbacks
    assert_equal [:before_1, :before_around_1, :before_2, :before_around_2, :after_around_2, :after_around_1, :after_1], @callbacks
  end
end

class TransitionWithBeforeCallbacksSkippedTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_not_run_before_callbacks
    @machine.before_transition {@run = true}
    
    assert_equal false, @transition.run_callbacks(:before => false)
    assert !@run
  end
  
  def test_should_run_failure_callbacks
    @machine.after_failure {@run = true}
    
    assert_equal false, @transition.run_callbacks(:before => false)
    assert @run
  end
end

class TransitionWithAfterCallbacksSkippedTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_run_before_callbacks
    @machine.before_transition {@run = true}
    
    assert_equal true, @transition.run_callbacks(:after => false)
    assert @run
  end
  
  def test_should_not_run_after_callbacks
    @machine.after_transition {@run = true}
    
    assert_equal true, @transition.run_callbacks(:after => false)
    assert !@run
  end
  
  if RUBY_PLATFORM != 'java'
    def test_should_run_around_callbacks_before_yield
      @machine.around_transition {|block| @run = true; block.call}
      
      assert_equal true, @transition.run_callbacks(:after => false)
      assert @run
    end
    
    def test_should_not_run_around_callbacks_after_yield
      @machine.around_transition {|block| block.call; @run = true}
      
      assert_equal true, @transition.run_callbacks(:after => false)
      assert !@run
    end
    
    def test_should_continue_around_transition_execution_on_second_call
      @callbacks = []
      @machine.around_transition {|block| @callbacks << :before_around_1; block.call; @callbacks << :after_around_1}
      @machine.around_transition {|block| @callbacks << :before_around_2; block.call; @callbacks << :after_around_2}
      @machine.after_transition {@callbacks << :after}
      
      assert_equal true, @transition.run_callbacks(:after => false)
      assert_equal [:before_around_1, :before_around_2], @callbacks
      
      assert_equal true, @transition.run_callbacks
      assert_equal [:before_around_1, :before_around_2, :after_around_2, :after_around_1, :after], @callbacks
    end
    
    def test_should_not_run_further_callbacks_if_halted_during_continue_around_transition
      @callbacks = []
      @machine.around_transition {|block| @callbacks << :before_around_1; block.call; @callbacks << :after_around_1}
      @machine.around_transition {|block| @callbacks << :before_around_2; block.call; @callbacks << :after_around_2; throw :halt}
      @machine.after_transition {@callbacks << :after}
      
      assert_equal true, @transition.run_callbacks(:after => false)
      assert_equal [:before_around_1, :before_around_2], @callbacks
      
      assert_equal true, @transition.run_callbacks
      assert_equal [:before_around_1, :before_around_2, :after_around_2], @callbacks
    end
    
    def test_should_not_be_able_to_continue_twice
      @count = 0
      @machine.around_transition {|block| block.call; @count += 1}
      @machine.after_transition {@count += 1}
      
      @transition.run_callbacks(:after => false)
      
      2.times do
        assert_equal true, @transition.run_callbacks
        assert_equal 2, @count
      end
    end
    
    def test_should_not_be_able_to_continue_again_after_halted
      @count = 0
      @machine.around_transition {|block| block.call; @count += 1; throw :halt}
      @machine.after_transition {@count += 1}
      
      @transition.run_callbacks(:after => false)
      
      2.times do
        assert_equal true, @transition.run_callbacks
        assert_equal 1, @count
      end
    end
    
    def test_should_have_access_to_result_after_continued
      @machine.around_transition {|block| @around_before_result = @transition.result; block.call; @around_after_result = @transition.result}
      @machine.after_transition {@after_result = @transition.result}
      
      @transition.run_callbacks(:after => false)
      @transition.run_callbacks {{:result => 1}}
      
      assert_nil @around_before_result
      assert_equal 1, @around_after_result
      assert_equal 1, @after_result
    end
    
    def test_should_raise_exceptions_during_around_callbacks_after_yield_in_second_execution
      @machine.around_transition {|block| block.call; raise ArgumentError}
      
      assert_nothing_raised { @transition.run_callbacks(:after => false) }
      assert_raise(ArgumentError) { @transition.run_callbacks }
    end
  else
    def test_should_raise_exception_on_second_call
      @callbacks = []
      @machine.around_transition {|block| @callbacks << :before_around_1; block.call; @callbacks << :after_around_1}
      @machine.around_transition {|block| @callbacks << :before_around_2; block.call; @callbacks << :after_around_2}
      @machine.after_transition {@callbacks << :after}
      
      assert_raise(ArgumentError) { @transition.run_callbacks(:after => false) }
    end
  end
end

class TransitionAfterBeingPerformedTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :saved, :save_state
      
      def save
        @save_state = state
        @saved = true
        1
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    @result = @transition.perform
  end
  
  def test_should_have_empty_args
    assert_equal [], @transition.args
  end
  
  def test_should_have_a_result
    assert_equal 1, @transition.result
  end
  
  def test_should_be_successful
    assert_equal true, @result
  end
  
  def test_should_change_the_current_state
    assert_equal 'idling', @object.state
  end
  
  def test_should_run_the_action
    assert @object.saved
  end
  
  def test_should_run_the_action_after_saving_the_state
    assert_equal 'idling', @object.save_state
  end
end

class TransitionWithPerformArgumentsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :saved
      
      def save
        @saved = true
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_have_arguments
    @transition.perform(1, 2)
    
    assert_equal [1, 2], @transition.args
    assert @object.saved
  end
  
  def test_should_not_include_run_action_in_arguments
    @transition.perform(1, 2, false)
    
    assert_equal [1, 2], @transition.args
    assert !@object.saved
  end
end

class TransitionWithoutRunningActionTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :saved
      
      def save
        @saved = true
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @machine.state :parked, :idling
    @machine.event :ignite
    @machine.after_transition {|object| @run_after = true}
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    @result = @transition.perform(false)
  end
  
  def test_should_have_empty_args
    assert_equal [], @transition.args
  end
  
  def test_should_not_have_a_result
    assert_nil @transition.result
  end
  
  def test_should_be_successful
    assert_equal true, @result
  end
  
  def test_should_change_the_current_state
    assert_equal 'idling', @object.state
  end
  
  def test_should_not_run_the_action
    assert !@object.saved
  end
  
  def test_should_run_after_callbacks
    assert @run_after
  end
end

class TransitionWithTransactionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      class << self
        attr_accessor :running_transaction
      end
      
      attr_accessor :result
      
      def save
        @result = self.class.running_transaction
        true
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    
    class << @machine
      def within_transaction(object)
        owner_class.running_transaction = object
        yield
        owner_class.running_transaction = false
      end
    end
  end
  
  def test_should_run_blocks_within_transaction_for_object
    @transition.within_transaction do
      @result = @klass.running_transaction
    end
    
    assert_equal @object, @result
  end
end

class TransitionTransientTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    @transition.transient = true
  end
  
  def test_should_be_transient
    assert @transition.transient?
  end
end

class TransitionEqualityTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def test_should_be_equal_with_same_properties
    transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    assert_equal transition, @transition
  end
  
  def test_should_not_be_equal_with_different_machines
    machine = StateMachine::Machine.new(@klass, :status, :namespace => :other)
    machine.state :parked, :idling
    machine.event :ignite
    transition = StateMachine::Transition.new(@object, machine, :ignite, :parked, :idling)
    
    assert_not_equal transition, @transition
  end
  
  def test_should_not_be_equal_with_different_objects
    transition = StateMachine::Transition.new(@klass.new, @machine, :ignite, :parked, :idling)
    assert_not_equal transition, @transition
  end
  
  def test_should_not_be_equal_with_different_event_names
    @machine.event :park
    transition = StateMachine::Transition.new(@object, @machine, :park, :parked, :idling)
    assert_not_equal transition, @transition
  end
  
  def test_should_not_be_equal_with_different_from_state_names
    @machine.state :first_gear
    transition = StateMachine::Transition.new(@object, @machine, :ignite, :first_gear, :idling)
    assert_not_equal transition, @transition
  end
  
  def test_should_not_be_equal_with_different_to_state_names
    @machine.state :first_gear
    transition = StateMachine::Transition.new(@object, @machine, :ignite, :idling, :first_gear)
    assert_not_equal transition, @transition
  end
end
