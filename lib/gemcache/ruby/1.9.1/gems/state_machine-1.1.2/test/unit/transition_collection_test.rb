require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class TransitionCollectionTest < Test::Unit::TestCase
  def test_should_raise_exception_if_invalid_option_specified
    exception = assert_raise(ArgumentError) {StateMachine::TransitionCollection.new([], :invalid => true)}
    
  end
  
  def test_should_raise_exception_if_multiple_transitions_for_same_attribute_specified
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @object = @klass.new
    
    exception = assert_raise(ArgumentError) do
      StateMachine::TransitionCollection.new([
        StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
        StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
      ])
    end
    assert_equal 'Cannot perform multiple transitions in parallel for the same state machine attribute', exception.message
  end
end

class TransitionCollectionByDefaultTest < Test::Unit::TestCase
  def setup
    @transitions = StateMachine::TransitionCollection.new
  end
  
  def test_should_not_skip_actions
    assert !@transitions.skip_actions
  end
  
  def test_should_not_skip_after
    assert !@transitions.skip_after
  end
  
  def test_should_use_transaction
    assert @transitions.use_transaction
  end
  
  def test_should_be_empty
    assert @transitions.empty?
  end
end

class TransitionCollectionEmptyWithoutBlockTest < Test::Unit::TestCase
  def setup
    @transitions = StateMachine::TransitionCollection.new
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
end


class TransitionCollectionEmptyWithBlockTest < Test::Unit::TestCase
  def setup
    @transitions = StateMachine::TransitionCollection.new
  end
  
  def test_should_raise_exception_if_perform_raises_exception
    assert_raise(ArgumentError) { @transitions.perform { raise ArgumentError } }
  end
  
  def test_should_use_block_result_if_non_boolean
    assert_equal 1, @transitions.perform { 1 }
  end
  
  def test_should_use_block_result_if_false
    assert_equal false, @transitions.perform { false }
  end
  
  def test_should_use_block_reslut_if_nil
    assert_equal nil, @transitions.perform { nil }
  end
end

class TransitionCollectionInvalidTest < Test::Unit::TestCase
  def setup
    @transitions = StateMachine::TransitionCollection.new([false])
  end
  
  def test_should_be_empty
    assert @transitions.empty?
  end
  
  def test_should_not_succeed
    assert_equal false, @transitions.perform
  end
  
  def test_should_not_run_perform_block
    ran_block = false
    @transitions.perform { ran_block = true }
    assert !ran_block
  end
end

class TransitionCollectionPartialInvalidTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_accessor :ran_transaction
    end
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @machine.state :idling
    @machine.event :ignite
    @machine.before_transition {@ran_before = true}
    @machine.after_transition {@ran_after = true}
    @machine.around_transition {|block| @ran_around_before = true; block.call; @ran_around_after = true}
    
    class << @machine
      def within_transaction(object)
        object.ran_transaction = true
      end
    end
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling),
      false
    ])
  end
  
  def test_should_not_store_invalid_values
    assert_equal 1, @transitions.length
  end
  
  def test_should_not_succeed
    assert_equal false, @transitions.perform
  end
  
  def test_should_not_start_transaction
    assert !@object.ran_transaction
  end
  
  def test_should_not_run_perform_block
    ran_block = false
    @transitions.perform { ran_block = true }
    assert !ran_block
  end
  
  def test_should_not_run_before_callbacks
    assert !@ran_before
  end
  
  def test_should_not_persist_states
    assert_equal 'parked', @object.state
  end
  
  def test_should_not_run_after_callbacks
    assert !@ran_after
  end
  
  def test_should_not_run_around_callbacks_before_yield
    assert !@ran_around_before
  end
  
  def test_should_not_run_around_callbacks_after_yield
    assert !@ran_around_after
  end
end

class TransitionCollectionValidTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :persisted
      
      def initialize
        super
        @persisted = []
      end
      
      def state=(value)
        @persisted << 'state' if @persisted
        @state = value
      end
      
      def status=(value)
        @persisted << 'status' if @persisted
        @status = value
      end
    end
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked)
    @state.state :idling
    @state.event :ignite
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    
    @result = StateMachine::TransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ]).perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_persist_each_state
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_persist_in_order
    assert_equal ['state', 'status'], @object.persisted
  end
  
  def test_should_store_results_in_transitions
    assert_nil @state_transition.result
    assert_nil @status_transition.result
  end
end

class TransitionCollectionWithoutTransactionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_accessor :ran_transaction
    end
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @machine.state :idling
    @machine.event :ignite
    
    class << @machine
      def within_transaction(object)
        object.ran_transaction = true
      end
    end
    
    @object = @klass.new
    @transitions = StateMachine::TransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ], :transaction => false)
    @transitions.perform
  end
  
  def test_should_not_run_within_transaction
    assert !@object.ran_transaction
  end
end

class TransitionCollectionWithTransactionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_accessor :running_transaction, :cancelled_transaction
    end
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @machine.state :idling
    @machine.event :ignite
    
    class << @machine
      def within_transaction(object)
        object.running_transaction = true
        object.cancelled_transaction = yield == false
        object.running_transaction = false
      end
    end
    
    @object = @klass.new
    @transitions = StateMachine::TransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ], :transaction => true)
  end
  
  def test_should_run_before_callbacks_within_transaction
    @machine.before_transition {|object| @in_transaction = object.running_transaction}
    @transitions.perform
    
    assert @in_transaction
  end
  
  def test_should_run_action_within_transaction
    @transitions.perform { @in_transaction = @object.running_transaction }
    
    assert @in_transaction
  end
  
  def test_should_run_after_callbacks_within_transaction
    @machine.after_transition {|object| @in_transaction = object.running_transaction}
    @transitions.perform
    
    assert @in_transaction
  end
  
  def test_should_cancel_the_transaction_on_before_halt
    @machine.before_transition {throw :halt}
    
    @transitions.perform
    assert @object.cancelled_transaction
  end
  
  def test_should_cancel_the_transaction_on_action_failure
    @transitions.perform { false }
    assert @object.cancelled_transaction
  end
  
  def test_should_not_cancel_the_transaction_on_after_halt
    @machine.after_transition {throw :halt}
    
    @transitions.perform
    assert !@object.cancelled_transaction
  end
end

class TransitionCollectionWithEmptyActionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
    
    @object.state = 'idling'
    @object.status = 'second_gear'
    
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_persist_states
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_store_results_in_transitions
    assert_nil @state_transition.result
    assert_nil @status_transition.result
  end
end

class TransitionCollectionWithSkippedActionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :actions
      
      def save_state
        (@actions ||= []) << :save_state
        :save_state
      end
      
      def save_status
        (@actions ||= []) << :save_status
        :save_status
      end
    end
    
    @callbacks = []
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save_state)
    @state.state :idling
    @state.event :ignite
    @state.before_transition {@callbacks << :state_before}
    @state.after_transition {@callbacks << :state_after}
    @state.around_transition {|block| @callbacks << :state_around_before; block.call; @callbacks << :state_around_after}
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save_status)
    @status.state :second_gear
    @status.event :shift_up
    @status.before_transition {@callbacks << :status_before}
    @status.after_transition {@callbacks << :status_after}
    @status.around_transition {|block| @callbacks << :status_around_before; block.call; @callbacks << :status_around_after}
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ], :actions => false)
    @result = @transitions.perform
  end
  
  def test_should_skip_actions
    assert_equal true, @transitions.skip_actions
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_persist_states
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_not_run_actions
    assert_nil @object.actions
  end
  
  def test_should_store_results_in_transitions
    assert_nil @state_transition.result
    assert_nil @status_transition.result
  end
  
  def test_should_run_all_callbacks
    assert_equal [:state_before, :state_around_before, :status_before, :status_around_before, :status_around_after, :status_after, :state_around_after, :state_after], @callbacks
  end
end

class TransitionCollectionWithSkippedActionsAndBlockTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save_state)
    @machine.state :idling
    @machine.event :ignite
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ], :actions => false)
    @result = @transitions.perform { @ran_block = true; 1 }
  end
  
  def test_should_succeed
    assert_equal 1, @result
  end
  
  def test_should_persist_states
    assert_equal 'idling', @object.state
  end
  
  def test_should_run_block
    assert @ran_block
  end
  
  def test_should_store_results_in_transitions
    assert_equal 1, @state_transition.result
  end
end

class TransitionCollectionWithDuplicateActionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :actions
      
      def save
        (@actions ||= []) << :save
        :save
      end
    end
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal :save, @result
  end
  
  def test_should_persist_states
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_run_action_once
    assert_equal [:save], @object.actions
  end
  
  def test_should_store_results_in_transitions
    assert_equal :save, @state_transition.result
    assert_equal :save, @status_transition.result
  end
end

class TransitionCollectionWithDifferentActionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :actions
      
      def save_state
        (@actions ||= []) << :save_state
        :save_state
      end
      
      def save_status
        (@actions ||= []) << :save_status
        :save_status
      end
    end
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save_state)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save_status)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
  end
  
  def test_should_succeed
    assert_equal true, @transitions.perform
  end
  
  def test_should_persist_states
    @transitions.perform
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_run_actions_in_order
    @transitions.perform
    assert_equal [:save_state, :save_status], @object.actions
  end
  
  def test_should_store_results_in_transitions
    @transitions.perform
    assert_equal :save_state, @state_transition.result
    assert_equal :save_status, @status_transition.result
  end
  
  def test_should_not_halt_if_action_fails_for_first_transition
    @klass.class_eval do
      def save_state
        (@actions ||= []) << :save_state
        false
      end
    end
    
    
    assert_equal false, @transitions.perform
    assert_equal [:save_state, :save_status], @object.actions
  end
  
  def test_should_halt_if_action_fails_for_second_transition
    @klass.class_eval do
      def save_status
        (@actions ||= []) << :save_status
        false
      end
    end
    
    assert_equal false, @transitions.perform
    assert_equal [:save_state, :save_status], @object.actions
  end
  
  def test_should_rollback_if_action_errors_for_first_transition
    @klass.class_eval do
      def save_state
        raise ArgumentError
      end
    end
    
    begin; @transitions.perform; rescue; end
    assert_equal 'parked', @object.state
    assert_equal 'first_gear', @object.status
  end
  
  def test_should_rollback_if_action_errors_for_second_transition
    @klass.class_eval do
      def save_status
        raise ArgumentError
      end
    end
    
    begin; @transitions.perform; rescue; end
    assert_equal 'parked', @object.state
    assert_equal 'first_gear', @object.status
  end
  
  def test_should_not_run_after_callbacks_if_action_fails_for_first_transition
    @klass.class_eval do
      def save_state
        false
      end
    end
    
    @callbacks = []
    @state.after_transition { @callbacks << :state_after }
    @state.around_transition {|block| block.call; @callbacks << :state_around }
    @status.after_transition { @callbacks << :status_after }
    @status.around_transition {|block| block.call; @callbacks << :status_around }
    
    @transitions.perform
    assert_equal [], @callbacks
  end
  
  def test_should_not_run_after_callbacks_if_action_fails_for_second_transition
    @klass.class_eval do
      def save_status
        false
      end
    end
    
    @callbacks = []
    @state.after_transition { @callbacks << :state_after }
    @state.around_transition {|block| block.call; @callbacks << :state_around }
    @status.after_transition { @callbacks << :status_after }
    @status.around_transition {|block| block.call; @callbacks << :status_around }
    
    @transitions.perform
    assert_equal [], @callbacks
  end
  
  def test_should_run_after_failure_callbacks_if_action_fails_for_first_transition
    @klass.class_eval do
      def save_state
        false
      end
    end
    
    @callbacks = []
    @state.after_failure { @callbacks << :state_after }
    @status.after_failure { @callbacks << :status_after }
    
    @transitions.perform
    assert_equal [:status_after, :state_after], @callbacks
  end
  
  def test_should_run_after_failure_callbacks_if_action_fails_for_second_transition
    @klass.class_eval do
      def save_status
        false
      end
    end
    
    @callbacks = []
    @state.after_failure { @callbacks << :state_after }
    @status.after_failure { @callbacks << :status_after }
    
    @transitions.perform
    assert_equal [:status_after, :state_after], @callbacks
  end
end

class TransitionCollectionWithMixedActionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def save
        true
      end
    end
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_persist_states
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_store_results_in_transitions
    assert_equal true, @state_transition.result
    assert_nil @status_transition.result
  end
end

class TransitionCollectionWithBlockTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :actions
      
      def save
        (@actions ||= []) << :save
      end
    end
    
    @state = StateMachine::Machine.new(@klass, :state, :initial => :parked, :action => :save)
    @state.state  :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    @transitions = StateMachine::TransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
    @result = @transitions.perform { 1 }
  end
  
  def test_should_succeed
    assert_equal 1, @result
  end
  
  def test_should_persist_states
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_not_run_machine_actions
    assert_nil @object.actions
  end
  
  def test_should_use_result_as_transition_result
    assert_equal 1, @state_transition.result
    assert_equal 1, @status_transition.result
  end
end

class TransitionCollectionWithActionFailedTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def save
        false
      end
    end
    @before_count = 0
    @around_before_count = 0
    @after_count = 0
    @around_after_count = 0
    @failure_count = 0
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.before_transition {@before_count += 1}
    @machine.after_transition {@after_count += 1}
    @machine.around_transition {|block| @around_before_count += 1; block.call; @around_after_count += 1}
    @machine.after_failure {@failure_count += 1}
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    @result = @transitions.perform
  end
  
  def test_should_not_succeed
    assert_equal false, @result
  end
  
  def test_should_not_persist_state
    assert_equal 'parked', @object.state
  end
  
  def test_should_run_before_callbacks
    assert_equal 1, @before_count
  end
  
  def test_should_run_around_callbacks_before_yield
    assert_equal 1, @around_before_count
  end
  
  def test_should_not_run_after_callbacks
    assert_equal 0, @after_count
  end
  
  def test_should_not_run_around_callbacks
    assert_equal 0, @around_after_count
  end
  
  def test_should_run_failure_callbacks
    assert_equal 1, @failure_count
  end
end

class TransitionCollectionWithActionErrorTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def save
        raise ArgumentError
      end
    end
    @before_count = 0
    @around_before_count = 0
    @after_count = 0
    @around_after_count = 0
    @failure_count = 0
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.before_transition {@before_count += 1}
    @machine.after_transition {@after_count += 1}
    @machine.around_transition {|block| @around_before_count += 1; block.call; @around_after_count += 1}
    @machine.after_failure {@failure_count += 1}
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    
    @raised = true
    begin
      @transitions.perform
      @raised = false
    rescue ArgumentError
    end
  end
  
  def test_should_not_catch_exception
    assert @raised
  end
  
  def test_should_not_persist_state
    assert_equal 'parked', @object.state
  end
  
  def test_should_run_before_callbacks
    assert_equal 1, @before_count
  end
  
  def test_should_run_around_callbacks_before_yield
    assert_equal 1, @around_before_count
  end
  
  def test_should_not_run_after_callbacks
    assert_equal 0, @after_count
  end
  
  def test_should_not_run_around_callbacks_after_yield
    assert_equal 0, @around_after_count
  end
  
  def test_should_not_run_failure_callbacks
    assert_equal 0, @failure_count
  end
end

class TransitionCollectionWithCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :saved
      
      def save
        @saved = true
      end
    end
    
    @before_callbacks = []
    @after_callbacks = []
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @state.state :idling
    @state.event :ignite
    @state.before_transition {@before_callbacks << :state_before}
    @state.after_transition {@after_callbacks << :state_after}
    @state.around_transition {|block| @before_callbacks << :state_around; block.call; @after_callbacks << :state_around}
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status.state :second_gear
    @status.event :shift_up
    @status.before_transition {@before_callbacks << :status_before}
    @status.after_transition {@after_callbacks << :status_after}
    @status.around_transition {|block| @before_callbacks << :status_around; block.call; @after_callbacks << :status_around}
    
    @object = @klass.new
    @transitions = StateMachine::TransitionCollection.new([
      StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
  end
  
  def test_should_run_before_callbacks_in_order
    @transitions.perform
    assert_equal [:state_before, :state_around, :status_before, :status_around], @before_callbacks
  end
  
  def test_should_halt_if_before_callback_halted_for_first_transition
    @state.before_transition {throw :halt}
    
    assert_equal false, @transitions.perform
    assert_equal [:state_before, :state_around], @before_callbacks
  end
  
  def test_should_halt_if_before_callback_halted_for_second_transition
    @status.before_transition {throw :halt}
    
    assert_equal false, @transitions.perform
    assert_equal [:state_before, :state_around, :status_before, :status_around], @before_callbacks
  end
  
  def test_should_halt_if_around_callback_halted_before_yield_for_first_transition
    @state.around_transition {throw :halt}
    
    assert_equal false, @transitions.perform
    assert_equal [:state_before, :state_around], @before_callbacks
  end
  
  def test_should_halt_if_around_callback_halted_before_yield_for_second_transition
    @status.around_transition {throw :halt}
    
    assert_equal false, @transitions.perform
    assert_equal [:state_before, :state_around, :status_before, :status_around], @before_callbacks
  end
  
  def test_should_run_after_callbacks_in_reverse_order
    @transitions.perform
    assert_equal [:status_around, :status_after, :state_around, :state_after], @after_callbacks
  end
  
  def test_should_not_halt_if_after_callback_halted_for_first_transition
    @state.after_transition {throw :halt}
    
    assert_equal true, @transitions.perform
    assert_equal [:status_around, :status_after, :state_around, :state_after], @after_callbacks
  end
  
  def test_should_not_halt_if_around_callback_halted_for_second_transition
    @status.around_transition {|block| block.call; throw :halt}
    
    assert_equal true, @transitions.perform
    assert_equal [:state_around, :state_after], @after_callbacks
  end

  def test_should_run_before_callbacks_before_persisting_the_state
    @state.before_transition {|object| @before_state = object.state}
    @state.around_transition {|object, transition, block| @around_state = object.state; block.call}
    @transitions.perform
    
    assert_equal 'parked', @before_state
    assert_equal 'parked', @around_state
  end
  
  def test_should_persist_state_before_running_action
    @klass.class_eval do
      attr_reader :saved_on_persist
      
      def state=(value)
        @state = value
        @saved_on_persist = @saved
      end
    end
    
    @transitions.perform
    assert !@object.saved_on_persist
  end
  
  def test_should_persist_state_before_running_action_block
    @klass.class_eval do
      attr_writer :saved
      attr_reader :saved_on_persist
      
      def state=(value)
        @state = value
        @saved_on_persist = @saved
      end
    end
    
    @transitions.perform { @object.saved = true }
    assert !@object.saved_on_persist
  end
  
  def test_should_run_after_callbacks_after_running_the_action
    @state.after_transition {|object| @after_saved = object.saved}
    @state.around_transition {|object, transition, block| block.call; @around_saved = object.saved}
    @transitions.perform
    
    assert @after_saved
    assert @around_saved
  end
end

class TransitionCollectionWithBeforeCallbackHaltTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :saved
      
      def save
        @saved = true
      end
    end
    @before_count = 0
    @after_count = 0
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.before_transition {@before_count += 1; throw :halt}
    @machine.before_transition {@before_count += 1}
    @machine.after_transition {@after_count += 1}
    @machine.around_transition {|block| @before_count += 1; block.call; @after_count += 1}
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    @result = @transitions.perform
  end
  
  def test_should_not_succeed
    assert_equal false, @result
  end
  
  def test_should_not_persist_state
    assert_equal 'parked', @object.state
  end
  
  def test_should_not_run_action
    assert !@object.saved
  end
  
  def test_should_not_run_further_before_callbacks
    assert_equal 1, @before_count
  end
  
  def test_should_not_run_after_callbacks
    assert_equal 0, @after_count
  end
end

class TransitionCollectionWithAfterCallbackHaltTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_reader :saved
      
      def save
        @saved = true
      end
    end
    @before_count = 0
    @after_count = 0
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.before_transition {@before_count += 1}
    @machine.after_transition {@after_count += 1; throw :halt}
    @machine.after_transition {@after_count += 1}
    @machine.around_transition {|block| @before_count += 1; block.call; @after_count += 1}
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_persist_state
    assert_equal 'idling', @object.state
  end
  
  def test_should_run_before_callbacks
    assert_equal 2, @before_count
  end
  
  def test_should_not_run_further_after_callbacks
    assert_equal 2, @after_count
  end
end

class TransitionCollectionWithSkippedAfterCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @machine.state :idling
    @machine.event :ignite
    @machine.after_transition {@ran_after = true}
    
    @object = @klass.new
    
    @transitions = StateMachine::TransitionCollection.new([
      @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ], :after => false)
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_not_run_after_callbacks
    assert !@ran_after
  end
  
  def test_should_run_after_callbacks_on_subsequent_perform
    StateMachine::TransitionCollection.new([@transition]).perform
    assert @ran_after
  end
end

if RUBY_PLATFORM != 'java'
  class TransitionCollectionWithSkippedAfterCallbacksAndAroundCallbacksTest < Test::Unit::TestCase
    def setup
      @klass = Class.new
      
      @machine = StateMachine::Machine.new(@klass, :initial => :parked)
      @machine.state :idling
      @machine.event :ignite
      @machine.around_transition {|block| @ran_around_before = true; block.call; @ran_around_after = true}
      
      @object = @klass.new
      
      @transitions = StateMachine::TransitionCollection.new([
        @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
      ], :after => false)
      @result = @transitions.perform
    end
    
    def test_should_succeed
      assert_equal true, @result
    end
    
    def test_should_not_run_around_callbacks_after_yield
      assert !@ran_around_after
    end
    
    def test_should_run_around_callbacks_after_yield_on_subsequent_perform
      StateMachine::TransitionCollection.new([@transition]).perform
      assert @ran_around_after
    end
    
    def test_should_not_rerun_around_callbacks_before_yield_on_subsequent_perform
      @ran_around_before = false
      StateMachine::TransitionCollection.new([@transition]).perform
      
      assert !@ran_around_before
    end
  end
else
  class TransitionCollectionWithSkippedAfterCallbacksAndAroundCallbacksTest < Test::Unit::TestCase
    def setup
      @klass = Class.new
      
      @machine = StateMachine::Machine.new(@klass, :initial => :parked)
      @machine.state :idling
      @machine.event :ignite
      @machine.around_transition {|block| @ran_around_before = true; block.call; @ran_around_after = true}
      
      @object = @klass.new
      
      @transitions = StateMachine::TransitionCollection.new([
        @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
      ], :after => false)
    end
    
    def test_should_raise_exception
      assert_raise(ArgumentError) { @transitions.perform }
    end
  end
end

class TransitionCollectionWithActionHookBaseTest < Test::Unit::TestCase
  def setup
    @superclass = Class.new do
      def save
        true
      end
    end
    
    @klass = Class.new(@superclass) do
      attr_reader :saved, :state_on_save, :state_event_on_save, :state_event_transition_on_save
      
      def save
        @saved = true
        @state_on_save = state
        @state_event_on_save = state_event
        @state_event_transition_on_save = state_event_transition
        super
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @object = @klass.new
    
    @transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end
  
  def default_test
  end
end

class TransitionCollectionWithActionHookAndSkippedActionTest < TransitionCollectionWithActionHookBaseTest
  def setup
    super
    @result = StateMachine::TransitionCollection.new([@transition], :actions => false).perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_not_run_action
    assert !@object.saved
  end
end

class TransitionCollectionWithActionHookAndSkippedAfterCallbacksTest < TransitionCollectionWithActionHookBaseTest
  def setup
    super
    @result = StateMachine::TransitionCollection.new([@transition], :after => false).perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_run_action
    assert @object.saved
  end
  
  def test_should_have_already_persisted_when_running_action
    assert_equal 'idling', @object.state_on_save
  end
  
  def test_should_not_have_event_during_action
    assert_nil @object.state_event_on_save
  end
  
  def test_should_not_write_event
    assert_nil @object.state_event
  end
  
  def test_should_not_have_event_transition_during_save
    assert_nil @object.state_event_transition_on_save
  end
  
  def test_should_not_write_event_attribute
    assert_nil @object.send(:state_event_transition)
  end
end

class TransitionCollectionWithActionHookAndBlockTest < TransitionCollectionWithActionHookBaseTest
  def setup
    super
    @result = StateMachine::TransitionCollection.new([@transition]).perform { true }
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_not_run_action
    assert !@object.saved
  end
end

class TransitionCollectionWithActionHookInvalidTest < TransitionCollectionWithActionHookBaseTest
  def setup
    super
    @result = StateMachine::TransitionCollection.new([@transition, nil]).perform
  end
  
  def test_should_not_succeed
    assert_equal false, @result
  end
  
  def test_should_not_run_action
    assert !@object.saved
  end
end

class TransitionCollectionWithActionHookWithNilActionTest < TransitionCollectionWithActionHookBaseTest
  def setup
    super
    
    @machine = StateMachine::Machine.new(@klass, :status, :initial => :first_gear)
    @machine.state :second_gear
    @machine.event :shift_up
    
    @result = StateMachine::TransitionCollection.new([@transition, StateMachine::Transition.new(@object, @machine, :shift_up, :first_gear, :second_gear)]).perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_run_action
    assert @object.saved
  end
  
  def test_should_have_already_persisted_when_running_action
    assert_equal 'idling', @object.state_on_save
  end
  
  def test_should_not_have_event_during_action
    assert_nil @object.state_event_on_save
  end
  
  def test_should_not_write_event
    assert_nil @object.state_event
  end
  
  def test_should_not_have_event_transition_during_save
    assert_nil @object.state_event_transition_on_save
  end
  
  def test_should_not_write_event_attribute
    assert_nil @object.send(:state_event_transition)
  end
end

class TransitionCollectionWithActionHookWithDifferentActionsTest < TransitionCollectionWithActionHookBaseTest
  def setup
    super
    
    @klass.class_eval do
      def save_status
        true
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save_status)
    @machine.state :second_gear
    @machine.event :shift_up
    
    @result = StateMachine::TransitionCollection.new([@transition, StateMachine::Transition.new(@object, @machine, :shift_up, :first_gear, :second_gear)]).perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_run_action
    assert @object.saved
  end
  
  def test_should_have_already_persisted_when_running_action
    assert_equal 'idling', @object.state_on_save
  end
  
  def test_should_not_have_event_during_action
    assert_nil @object.state_event_on_save
  end
  
  def test_should_not_write_event
    assert_nil @object.state_event
  end
  
  def test_should_not_have_event_transition_during_save
    assert_nil @object.state_event_transition_on_save
  end
  
  def test_should_not_write_event_attribute
    assert_nil @object.send(:state_event_transition)
  end
end

class TransitionCollectionWithActionHookTest < TransitionCollectionWithActionHookBaseTest
  def setup
    super
    @result = StateMachine::TransitionCollection.new([@transition]).perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_run_action
    assert @object.saved
  end
  
  def test_should_not_have_already_persisted_when_running_action
    assert_equal 'parked', @object.state_on_save
  end
  
  def test_should_persist
    assert_equal 'idling', @object.state
  end
  
  def test_should_not_have_event_during_action
    assert_nil @object.state_event_on_save
  end
  
  def test_should_not_write_event
    assert_nil @object.state_event
  end
  
  def test_should_have_event_transition_during_action
    assert_equal @transition, @object.state_event_transition_on_save
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
  
  def test_should_mark_event_transition_as_transient
    assert @transition.transient?
  end
end

class TransitionCollectionWithActionHookMultipleTest < TransitionCollectionWithActionHookBaseTest
  def setup
    super
    
    @status_machine = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status_machine.state :second_gear
    @status_machine.event :shift_up
    
    @klass.class_eval do
      attr_reader :status_on_save, :status_event_on_save, :status_event_transition_on_save
      
      def save
        @saved = true
        @state_on_save = state
        @state_event_on_save = state_event
        @state_event_transition_on_save = state_event_transition
        @status_on_save = status
        @status_event_on_save = status_event
        @status_event_transition_on_save = status_event_transition
        super
        1
      end
    end
    
    @object = @klass.new
    @state_transition = StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    @status_transition = StateMachine::Transition.new(@object, @status_machine, :shift_up, :first_gear, :second_gear)
    
    @result = StateMachine::TransitionCollection.new([@state_transition, @status_transition]).perform
  end
  
  def test_should_succeed
    assert_equal 1, @result
  end
  
  def test_should_run_action
    assert @object.saved
  end
  
  def test_should_not_have_already_persisted_when_running_action
    assert_equal 'parked', @object.state_on_save
    assert_equal 'first_gear', @object.status_on_save
  end
  
  def test_should_persist
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_not_have_events_during_action
    assert_nil @object.state_event_on_save
    assert_nil @object.status_event_on_save
  end
  
  def test_should_not_write_events
    assert_nil @object.state_event
    assert_nil @object.status_event
  end
  
  def test_should_have_event_transitions_during_action
    assert_equal @state_transition, @object.state_event_transition_on_save
    assert_equal @status_transition, @object.status_event_transition_on_save
  end
  
  def test_should_not_write_event_transitions
    assert_nil @object.send(:state_event_transition)
    assert_nil @object.send(:status_event_transition)
  end
  
  def test_should_mark_event_transitions_as_transient
    assert @state_transition.transient?
    assert @status_transition.transient?
  end
end

class TransitionCollectionWithActionHookErrorTest < TransitionCollectionWithActionHookBaseTest
  def setup
    super
    
    @superclass.class_eval do
      def save
        raise ArgumentError
      end
    end
    
    begin; StateMachine::TransitionCollection.new([@transition]).perform; rescue; end
  end
  
  def test_should_not_write_event
    assert_nil @object.state_event
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
end

class AttributeTransitionCollectionByDefaultTest < Test::Unit::TestCase
  def setup
    @transitions = StateMachine::AttributeTransitionCollection.new
  end
  
  def test_should_skip_actions
    assert @transitions.skip_actions
  end
  
  def test_should_not_skip_after
    assert !@transitions.skip_after
  end
  
  def test_should_not_use_transaction
    assert !@transitions.use_transaction
  end
  
  def test_should_be_empty
    assert @transitions.empty?
  end
end

class AttributeTransitionCollectionWithEventsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    @object.state_event = 'ignite'
    @object.status_event = 'shift_up'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_persist_states
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_clear_events
    assert_nil @object.state_event
    assert_nil @object.status_event
  end
  
  def test_should_not_write_event_transitions
    assert_nil @object.send(:state_event_transition)
    assert_nil @object.send(:status_event_transition)
  end
end

class AttributeTransitionCollectionWithEventTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    @object.send(:state_event_transition=, @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling))
    @object.send(:status_event_transition=, @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear))
    
    @transitions = StateMachine::AttributeTransitionCollection.new([@state_transition, @status_transition])
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_persist_states
    assert_equal 'idling', @object.state
    assert_equal 'second_gear', @object.status
  end
  
  def test_should_not_write_events
    assert_nil @object.state_event
    assert_nil @object.status_event
  end
  
  def test_should_clear_event_transitions
    assert_nil @object.send(:state_event_transition)
    assert_nil @object.send(:status_event_transition)
  end
end

class AttributeTransitionCollectionWithActionFailedTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    @object.state_event = 'ignite'
    @object.status_event = 'shift_up'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
    @result = @transitions.perform { false }
  end
  
  def test_should_not_succeed
    assert_equal false, @result
  end
  
  def test_should_not_persist_states
    assert_equal 'parked', @object.state
    assert_equal 'first_gear', @object.status
  end
  
  def test_should_not_clear_events
    assert_equal :ignite, @object.state_event
    assert_equal :shift_up, @object.status_event
  end
  
  def test_should_not_write_event_transitions
    assert_nil @object.send(:state_event_transition)
    assert_nil @object.send(:status_event_transition)
  end
end

class AttributeTransitionCollectionWithActionErrorTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    @object.state_event = 'ignite'
    @object.status_event = 'shift_up'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
    
    begin; @transitions.perform { raise ArgumentError }; rescue; end
  end
  
  def test_should_not_persist_states
    assert_equal 'parked', @object.state
    assert_equal 'first_gear', @object.status
  end
  
  def test_should_not_clear_events
    assert_equal :ignite, @object.state_event
    assert_equal :shift_up, @object.status_event
  end
  
  def test_should_not_write_event_transitions
    assert_nil @object.send(:state_event_transition)
    assert_nil @object.send(:status_event_transition)
  end
end

class AttributeTransitionCollectionWithCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ])
  end
  
  def test_should_not_have_events_during_before_callbacks
    @state.before_transition {|object, transition| @before_state_event = object.state_event }
    @state.around_transition {|object, transition, block| @around_state_event = object.state_event; block.call }
    @transitions.perform
    
    assert_nil @before_state_event
    assert_nil @around_state_event
  end
  
  def test_should_not_have_events_during_action
    @transitions.perform { @state_event = @object.state_event }
    
    assert_nil @state_event
  end
  
  def test_should_not_have_events_during_after_callbacks
    @state.after_transition {|object, transition| @after_state_event = object.state_event }
    @state.around_transition {|object, transition, block| block.call; @around_state_event = object.state_event }
    @transitions.perform
    
    assert_nil @state_event
  end
  
  def test_should_not_have_event_transitions_during_before_callbacks
    @state.before_transition {|object, transition| @state_event_transition = object.send(:state_event_transition) }
    @transitions.perform
    
    assert_nil @state_event_transition
  end
  
  def test_should_not_have_event_transitions_during_action
    @transitions.perform { @state_event_transition = @object.send(:state_event_transition) }
    
    assert_nil @state_event_transition
  end
  
  def test_should_not_have_event_transitions_during_after_callbacks
    @state.after_transition {|object, transition| @after_state_event_transition = object.send(:state_event_transition) }
    @state.around_transition {|object, transition, block| block.call; @around_state_event_transition = object.send(:state_event_transition) }
    @transitions.perform
    
    assert_nil @after_state_event_transition
    assert_nil @around_state_event_transition
  end
end

class AttributeTransitionCollectionWithBeforeCallbackHaltTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.before_transition {throw :halt}
    
    @object = @klass.new
    @object.state_event = 'ignite'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    @result = @transitions.perform
  end
  
  def test_should_not_succeed
    assert_equal false, @result
  end
  
  def test_should_not_clear_event
    assert_equal :ignite, @object.state_event
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
end

class AttributeTransitionCollectionWithBeforeCallbackErrorTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.before_transition {raise ArgumentError}
    
    @object = @klass.new
    @object.state_event = 'ignite'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    begin; @transitions.perform; rescue; end
  end
  
  def test_should_not_clear_event
    assert_equal :ignite, @object.state_event
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
end

class AttributeTransitionCollectionWithAroundCallbackBeforeYieldHaltTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.around_transition {throw :halt}
    
    @object = @klass.new
    @object.state_event = 'ignite'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    @result = @transitions.perform
  end
  
  def test_should_not_succeed
    assert_equal false, @result
  end
  
  def test_should_not_clear_event
    assert_equal :ignite, @object.state_event
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
end

class AttributeTransitionCollectionWithAroundAfterYieldCallbackErrorTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.before_transition {raise ArgumentError}
    
    @object = @klass.new
    @object.state_event = 'ignite'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    begin; @transitions.perform; rescue; end
  end
  
  def test_should_not_clear_event
    assert_equal :ignite, @object.state_event
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
end

class AttributeTransitionCollectionWithSkippedAfterCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @state = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @state.state :idling
    @state.event :ignite
    
    @status = StateMachine::Machine.new(@klass, :status, :initial => :first_gear, :action => :save)
    @status.state :second_gear
    @status.event :shift_up
    
    @object = @klass.new
    @object.state_event = 'ignite'
    @object.status_event = 'shift_up'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      @state_transition = StateMachine::Transition.new(@object, @state, :ignite, :parked, :idling),
      @status_transition = StateMachine::Transition.new(@object, @status, :shift_up, :first_gear, :second_gear)
    ], :after => false)
  end
  
  def test_should_clear_events
    @transitions.perform
    assert_nil @object.state_event
    assert_nil @object.status_event
  end
  
  def test_should_write_event_transitions_if_success
    @transitions.perform { true }
    assert_equal @state_transition, @object.send(:state_event_transition)
    assert_equal @status_transition, @object.send(:status_event_transition)
  end
  
  def test_should_not_write_event_transitions_if_failed
    @transitions.perform { false }
    assert_nil @object.send(:state_event_transition)
    assert_nil @object.send(:status_event_transition)
  end
end

class AttributeTransitionCollectionWithAfterCallbackHaltTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.after_transition {throw :halt}
    
    @object = @klass.new
    @object.state_event = 'ignite'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_clear_event
    assert_nil @object.state_event
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
end

class AttributeTransitionCollectionWithAfterCallbackErrorTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.after_transition {raise ArgumentError}
    
    @object = @klass.new
    @object.state_event = 'ignite'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    begin; @transitions.perform; rescue; end
  end
  
  def test_should_clear_event
    assert_nil @object.state_event
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
end

class AttributeTransitionCollectionWithAroundCallbackAfterYieldHaltTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.around_transition {|block| block.call; throw :halt}
    
    @object = @klass.new
    @object.state_event = 'ignite'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    @result = @transitions.perform
  end
  
  def test_should_succeed
    assert_equal true, @result
  end
  
  def test_should_clear_event
    assert_nil @object.state_event
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
end

class AttributeTransitionCollectionWithAfterCallbackErrorTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @machine.around_transition {|block| block.call; raise ArgumentError}
    
    @object = @klass.new
    @object.state_event = 'ignite'
    
    @transitions = StateMachine::AttributeTransitionCollection.new([
      StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
    ])
    begin; @transitions.perform; rescue; end
  end
  
  def test_should_clear_event
    assert_nil @object.state_event
  end
  
  def test_should_not_write_event_transition
    assert_nil @object.send(:state_event_transition)
  end
end

class AttributeTransitionCollectionMarshallingTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    self.class.const_set('Example', @klass)
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :action => :save)
    @machine.state :idling
    @machine.event :ignite
    
    @object = @klass.new
    @object.state_event = 'ignite'
  end
  
  def test_should_marshal_during_before_callbacks
    @machine.before_transition {|object, transition| Marshal.dump(object)}
    assert_nothing_raised do
      transitions(:after => false).perform { true }
      transitions.perform { true }
    end
  end
  
  def test_should_marshal_during_action
    assert_nothing_raised do
      transitions(:after => false).perform do
         Marshal.dump(@object)
         true
      end
      
      transitions.perform do
         Marshal.dump(@object)
         true
      end
    end
  end
  
  def test_should_marshal_during_after_callbacks
    @machine.after_transition {|object, transition| Marshal.dump(object)}
    assert_nothing_raised do
      transitions(:after => false).perform { true }
      transitions.perform { true }
    end
  end
  
  if RUBY_PLATFORM != 'java'
    def test_should_marshal_during_around_callbacks_before_yield
      @machine.around_transition {|object, transition, block| Marshal.dump(object); block.call}
      assert_nothing_raised do
        transitions(:after => false).perform { true }
        transitions.perform { true }
      end
    end
    
    def test_should_marshal_during_around_callbacks_after_yield
      @machine.around_transition {|object, transition, block| block.call; Marshal.dump(object)}
      assert_nothing_raised do
        transitions(:after => false).perform { true }
        transitions.perform { true }
      end
    end
  end
  
  def teardown
    self.class.send(:remove_const, 'Example')
  end
  
  private
    def transitions(options = {})
      StateMachine::AttributeTransitionCollection.new([
        StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)
      ], options)
    end
end
