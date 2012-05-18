require File.expand_path(File.dirname(__FILE__) + '/../../test_helper')

require 'active_model'
require 'active_model/observing'
require 'active_support/all'

module ActiveModelTest
  class BaseTestCase < Test::Unit::TestCase
    def default_test
    end
    
    protected
      # Creates a new ActiveModel model (and the associated table)
      def new_model(&block)
        # Simple ActiveModel superclass
        parent = Class.new do
          def self.model_attribute(name)
            define_method(name) { instance_variable_get("@#{name}") }
            define_method("#{name}=") do |value|
              send("#{name}_will_change!") if self.class <= ActiveModel::Dirty && value != instance_variable_get("@#{name}")
              instance_variable_set("@#{name}", value)
            end
          end
          
          def self.create
            object = new
            object.save
            object
          end
          
          def initialize(attrs = {})
            attrs.each {|attr, value| send("#{attr}=", value)}
            @changed_attributes = {}
          end
          
          def attributes
            @attributes ||= {}
          end
          
          def save
            @changed_attributes = {}
            true
          end
        end
        
        model = Class.new(parent) do
          def self.name
            'ActiveModelTest::Foo'
          end
          
          model_attribute :state
        end
        model.class_eval(&block) if block_given?
        model
      end
      
      # Creates a new ActiveModel observer
      def new_observer(model, &block)
        observer = Class.new(ActiveModel::Observer) do
          attr_accessor :notifications
          
          def initialize
            super
            @notifications = []
          end
        end
        observer.observe(model)
        observer.class_eval(&block) if block_given?
        observer
      end
  end
  
  class IntegrationTest < BaseTestCase
    def test_should_have_an_integration_name
      assert_equal :active_model, StateMachine::Integrations::ActiveModel.integration_name
    end
    
    def test_should_be_available
      assert StateMachine::Integrations::ActiveModel.available?
    end
    
    def test_should_match_if_class_includes_observing_feature
      assert StateMachine::Integrations::ActiveModel.matches?(new_model { include ActiveModel::Observing })
    end
    
    def test_should_match_if_class_includes_validations_feature
      assert StateMachine::Integrations::ActiveModel.matches?(new_model { include ActiveModel::Validations })
    end
    
    def test_should_not_match_if_class_does_not_include_active_model_features
      assert !StateMachine::Integrations::ActiveModel.matches?(new_model)
    end
    
    def test_should_have_no_defaults
      assert_equal e = {}, StateMachine::Integrations::ActiveModel.defaults
    end
    
    def test_should_have_a_locale_path
      assert_not_nil StateMachine::Integrations::ActiveModel.locale_path
    end
  end
  
  class MachineByDefaultTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :integration => :active_model)
    end
    
    def test_should_not_have_action
      assert_nil @machine.action
    end
    
    def test_should_use_transactions
      assert_equal true, @machine.use_transactions
    end
    
    def test_should_not_have_any_before_callbacks
      assert_equal 0, @machine.callbacks[:before].size
    end
    
    def test_should_not_have_any_after_callbacks
      assert_equal 0, @machine.callbacks[:after].size
    end
  end
  
  class MachineWithStatesTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.state :first_gear
    end
    
    def test_should_humanize_name
      assert_equal 'first gear', @machine.state(:first_gear).human_name
    end
  end
  
  class MachineWithStaticInitialStateTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked, :integration => :active_model)
    end
    
    def test_should_set_initial_state_on_created_object
      record = @model.new
      assert_equal 'parked', record.state
    end
  end
  
  class MachineWithDynamicInitialStateTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => lambda {|object| :parked}, :integration => :active_model)
      @machine.state :parked
    end
    
    def test_should_set_initial_state_on_created_object
      record = @model.new
      assert_equal 'parked', record.state
    end
  end
  
  class MachineWithEventsTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.event :shift_up
    end
    
    def test_should_humanize_name
      assert_equal 'shift up', @machine.event(:shift_up).human_name
    end
  end
  
  class MachineWithModelStateAttributeTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked, :integration => :active_model)
      @machine.other_states(:idling)
      
      @record = @model.new
    end
    
    def test_should_have_an_attribute_predicate
      assert @record.respond_to?(:state?)
    end
    
    def test_should_raise_exception_for_predicate_without_parameters
      exception = assert_raise(ArgumentError) { @record.state? }
      assert_equal 'wrong number of arguments (1 for 2)', exception.message
    end
    
    def test_should_return_false_for_predicate_if_does_not_match_current_value
      assert !@record.state?(:idling)
    end
    
    def test_should_return_true_for_predicate_if_matches_current_value
      assert @record.state?(:parked)
    end
    
    def test_should_raise_exception_for_predicate_if_invalid_state_specified
      assert_raise(IndexError) { @record.state?(:invalid) }
    end
  end
  
  class MachineWithNonModelStateAttributeUndefinedTest < BaseTestCase
    def setup
      @model = new_model do
        def initialize
        end
      end
      
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked, :integration => :active_model)
      @machine.other_states(:idling)
      @record = @model.new
    end
    
    def test_should_not_define_a_reader_attribute_for_the_attribute
      assert !@record.respond_to?(:status)
    end
    
    def test_should_not_define_a_writer_attribute_for_the_attribute
      assert !@record.respond_to?(:status=)
    end
    
    def test_should_define_an_attribute_predicate
      assert @record.respond_to?(:status?)
    end
  end
  
  class MachineWithInitializedStateTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked, :integration => :active_model)
      @machine.state nil, :idling
    end
    
    def test_should_allow_nil_initial_state_when_static
      @machine.state nil
      
      record = @model.new(:state => nil)
      assert_nil record.state
    end
    
    def test_should_allow_nil_initial_state_when_dynamic
      @machine.state nil
      
      @machine.initial_state = lambda {:parked}
      record = @model.new(:state => nil)
      assert_nil record.state
    end
    
    def test_should_allow_different_initial_state_when_static
      record = @model.new(:state => 'idling')
      assert_equal 'idling', record.state
    end
    
    def test_should_allow_different_initial_state_when_dynamic
      @machine.initial_state = lambda {:parked}
      record = @model.new(:state => 'idling')
      assert_equal 'idling', record.state
    end
    
    def test_should_use_default_state_if_protected
      @model.class_eval do
        include ActiveModel::MassAssignmentSecurity
        attr_protected :state
        
        def initialize(attrs = {})
          initialize_state_machines do
            sanitize_for_mass_assignment(attrs).each {|attr, value| send("#{attr}=", value)} if attrs
            @changed_attributes = {}
          end
        end
      end
      
      record = @model.new(:state => 'idling')
      assert_equal 'parked', record.state
      
      record = @model.new(nil)
      assert_equal 'parked', record.state
    end
  end
  
  class MachineMultipleTest < BaseTestCase
    def setup
      @model = new_model do
        model_attribute :status
      end
      
      @state_machine = StateMachine::Machine.new(@model, :initial => :parked, :integration => :active_model)
      @status_machine = StateMachine::Machine.new(@model, :status, :initial => :idling, :integration => :active_model)
    end
    
    def test_should_should_initialize_each_state
      record = @model.new
      assert_equal 'parked', record.state
      assert_equal 'idling', record.status
    end
  end
  
  class MachineWithDirtyAttributesTest < BaseTestCase
    def setup
      @model = new_model do
        include ActiveModel::Dirty
        define_attribute_methods [:state]
      end
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.event :ignite
      @machine.state :idling
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @transition.perform
    end
    
    def test_should_include_state_in_changed_attributes
      assert_equal %w(state), @record.changed
    end
    
    def test_should_track_attribute_change
      assert_equal %w(parked idling), @record.changes['state']
    end
    
    def test_should_not_reset_changes_on_multiple_transitions
      transition = StateMachine::Transition.new(@record, @machine, :ignite, :idling, :idling)
      transition.perform
      
      assert_equal %w(parked idling), @record.changes['state']
    end
  end
  
  class MachineWithDirtyAttributesDuringLoopbackTest < BaseTestCase
    def setup
      @model = new_model do
        include ActiveModel::Dirty
        define_attribute_methods [:state]
      end
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.event :park
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :park, :parked, :parked)
      @transition.perform
    end
    
    def test_should_not_include_state_in_changed_attributes
      assert_equal [], @record.changed
    end
    
    def test_should_not_track_attribute_changes
      assert_equal nil, @record.changes['state']
    end
  end
  
  class MachineWithDirtyAttributesAndCustomAttributeTest < BaseTestCase
    def setup
      @model = new_model do
        include ActiveModel::Dirty
        model_attribute :status
        define_attribute_methods [:status]
      end
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
      @machine.event :ignite
      @machine.state :idling
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @transition.perform
    end
    
    def test_should_include_state_in_changed_attributes
      assert_equal %w(status), @record.changed
    end
    
    def test_should_track_attribute_change
      assert_equal %w(parked idling), @record.changes['status']
    end
    
    def test_should_not_reset_changes_on_multiple_transitions
      transition = StateMachine::Transition.new(@record, @machine, :ignite, :idling, :idling)
      transition.perform
      
      assert_equal %w(parked idling), @record.changes['status']
    end
  end
  
  class MachineWithDirtyAttributeAndCustomAttributesDuringLoopbackTest < BaseTestCase
    def setup
      @model = new_model do
        include ActiveModel::Dirty
        model_attribute :status
        define_attribute_methods [:status]
      end
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
      @machine.event :park
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :park, :parked, :parked)
      @transition.perform
    end
    
    def test_should_not_include_state_in_changed_attributes
      assert_equal [], @record.changed
    end
    
    def test_should_not_track_attribute_changes
      assert_equal nil, @record.changes['status']
    end
  end
  
  class MachineWithDirtyAttributeAndStateEventsTest < BaseTestCase
    def setup
      @model = new_model do
        include ActiveModel::Dirty
        define_attribute_methods [:state]
      end
      @machine = StateMachine::Machine.new(@model, :action => :save, :initial => :parked)
      @machine.event :ignite
      
      @record = @model.create
      @record.state_event = 'ignite'
    end
    
    def test_should_not_include_state_in_changed_attributes
      assert_equal [], @record.changed
    end
    
    def test_should_not_track_attribute_change
      assert_equal nil, @record.changes['state']
    end
  end
  
  class MachineWithCallbacksTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked, :integration => :active_model)
      @machine.other_states :idling
      @machine.event :ignite
      
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
    end
    
    def test_should_run_before_callbacks
      called = false
      @machine.before_transition {called = true}
      
      @transition.perform
      assert called
    end
    
    def test_should_pass_record_to_before_callbacks_with_one_argument
      record = nil
      @machine.before_transition {|arg| record = arg}
      
      @transition.perform
      assert_equal @record, record
    end
    
    def test_should_pass_record_and_transition_to_before_callbacks_with_multiple_arguments
      callback_args = nil
      @machine.before_transition {|*args| callback_args = args}
      
      @transition.perform
      assert_equal [@record, @transition], callback_args
    end
    
    def test_should_run_before_callbacks_outside_the_context_of_the_record
      context = nil
      @machine.before_transition {context = self}
      
      @transition.perform
      assert_equal self, context
    end
    
    def test_should_run_after_callbacks
      called = false
      @machine.after_transition {called = true}
      
      @transition.perform
      assert called
    end
    
    def test_should_pass_record_to_after_callbacks_with_one_argument
      record = nil
      @machine.after_transition {|arg| record = arg}
      
      @transition.perform
      assert_equal @record, record
    end
    
    def test_should_pass_record_and_transition_to_after_callbacks_with_multiple_arguments
      callback_args = nil
      @machine.after_transition {|*args| callback_args = args}
      
      @transition.perform
      assert_equal [@record, @transition], callback_args
    end
    
    def test_should_run_after_callbacks_outside_the_context_of_the_record
      context = nil
      @machine.after_transition {context = self}
      
      @transition.perform
      assert_equal self, context
    end
    
    def test_should_run_around_callbacks
      before_called = false
      after_called = false
      @machine.around_transition {|block| before_called = true; block.call; after_called = true}
      
      @transition.perform
      assert before_called
      assert after_called
    end
    
    def test_should_include_transition_states_in_known_states
      @machine.before_transition :to => :first_gear, :do => lambda {}
      
      assert_equal [:parked, :idling, :first_gear], @machine.states.map {|state| state.name}
    end
    
    def test_should_allow_symbolic_callbacks
      callback_args = nil
      
      klass = class << @record; self; end
      klass.send(:define_method, :after_ignite) do |*args|
        callback_args = args
      end
      
      @machine.before_transition(:after_ignite)
      
      @transition.perform
      assert_equal [@transition], callback_args
    end
    
    def test_should_allow_string_callbacks
      class << @record
        attr_reader :callback_result
      end
      
      @machine.before_transition('@callback_result = [1, 2, 3]')
      @transition.perform
      
      assert_equal [1, 2, 3], @record.callback_result
    end
  end
  
  class MachineWithFailedBeforeCallbacksTest < BaseTestCase
    def setup
      @callbacks = []
      
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :integration => :active_model)
      @machine.state :parked, :idling
      @machine.event :ignite
      @machine.before_transition {@callbacks << :before_1; false}
      @machine.before_transition {@callbacks << :before_2}
      @machine.after_transition {@callbacks << :after}
      @machine.around_transition {|block| @callbacks << :around_before; block.call; @callbacks << :around_after}
      
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @result = @transition.perform
    end
    
    def test_should_not_be_successful
      assert !@result
    end
    
    def test_should_not_change_current_state
      assert_equal 'parked', @record.state
    end
    
    def test_should_not_run_further_callbacks
      assert_equal [:before_1], @callbacks
    end
  end
  
  class MachineWithFailedAfterCallbacksTest < BaseTestCase
     def setup
      @callbacks = []
      
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :integration => :active_model)
      @machine.state :parked, :idling
      @machine.event :ignite
      @machine.after_transition {@callbacks << :after_1; false}
      @machine.after_transition {@callbacks << :after_2}
      @machine.around_transition {|block| @callbacks << :around_before; block.call; @callbacks << :around_after}
      
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @result = @transition.perform
    end
    
    def test_should_be_successful
      assert @result
    end
    
    def test_should_change_current_state
      assert_equal 'idling', @record.state
    end
    
    def test_should_not_run_further_after_callbacks
      assert_equal [:around_before, :around_after, :after_1], @callbacks
    end
  end
  
  class MachineWithValidationsTest < BaseTestCase
    def setup
      @model = new_model { include ActiveModel::Validations }
      @machine = StateMachine::Machine.new(@model, :action => :save)
      @machine.state :parked
      
      @record = @model.new
    end
    
    def test_should_invalidate_using_errors
      I18n.backend = I18n::Backend::Simple.new if Object.const_defined?(:I18n)
      @record.state = 'parked'
      
      @machine.invalidate(@record, :state, :invalid_transition, [[:event, 'park']])
      assert_equal ['State cannot transition via "park"'], @record.errors.full_messages
    end
    
    def test_should_auto_prefix_custom_attributes_on_invalidation
      @machine.invalidate(@record, :event, :invalid)
      
      assert_equal ['State event is invalid'], @record.errors.full_messages
    end
    
    def test_should_clear_errors_on_reset
      @record.state = 'parked'
      @record.errors.add(:state, 'is invalid')
      
      @machine.reset(@record)
      assert_equal [], @record.errors.full_messages
    end
    
    def test_should_be_valid_if_state_is_known
      @record.state = 'parked'
      
      assert @record.valid?
    end
    
    def test_should_not_be_valid_if_state_is_unknown
      @record.state = 'invalid'
      
      assert !@record.valid?
      assert_equal ['State is invalid'], @record.errors.full_messages
    end
  end
  
  class MachineWithValidationsAndCustomAttributeTest < BaseTestCase
    def setup
      @model = new_model { include ActiveModel::Validations }
      
      @machine = StateMachine::Machine.new(@model, :status, :attribute => :state)
      @machine.state :parked
      
      @record = @model.new
    end
    
    def test_should_add_validation_errors_to_custom_attribute
      @record.state = 'invalid'
      
      assert !@record.valid?
      assert_equal ['State is invalid'], @record.errors.full_messages
      
      @record.state = 'parked'
      assert @record.valid?
    end
  end
  
  class MachineErrorsTest < BaseTestCase
    def setup
      @model = new_model { include ActiveModel::Validations }
      @machine = StateMachine::Machine.new(@model)
      @record = @model.new
    end
    
    def test_should_be_able_to_describe_current_errors
      @record.errors.add(:id, 'cannot be blank')
      @record.errors.add(:state, 'is invalid')
      assert_equal ['Id cannot be blank', 'State is invalid'], @machine.errors_for(@record).split(', ').sort
    end
    
    def test_should_describe_as_halted_with_no_errors
      assert_equal 'Transition halted', @machine.errors_for(@record)
    end
  end
    
  class MachineWithStateDrivenValidationsTest < BaseTestCase
    def setup
      @model = new_model do
        include ActiveModel::Validations
        attr_accessor :seatbelt
      end
      
      @machine = StateMachine::Machine.new(@model)
      @machine.state :first_gear, :second_gear do
        validates_presence_of :seatbelt
      end
      @machine.other_states :parked
    end
    
    def test_should_be_valid_if_validation_fails_outside_state_scope
      record = @model.new(:state => 'parked', :seatbelt => nil)
      assert record.valid?
    end
    
    def test_should_be_invalid_if_validation_fails_within_state_scope
      record = @model.new(:state => 'first_gear', :seatbelt => nil)
      assert !record.valid?
    end
    
    def test_should_be_valid_if_validation_succeeds_within_state_scope
      record = @model.new(:state => 'second_gear', :seatbelt => true)
      assert record.valid?
    end
  end
  
  class ObserverUpdateTest < BaseTestCase
    def setup
      @model = new_model { include ActiveModel::Observing }
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :idling
      @machine.event :ignite
      
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      
      @observer_update = StateMachine::Integrations::ActiveModel::ObserverUpdate.new(:before_transition, @record, @transition)
    end
    
    def test_should_have_method
      assert_equal :before_transition, @observer_update.method
    end
    
    def test_should_have_object
      assert_equal @record, @observer_update.object
    end
    
    def test_should_have_transition
      assert_equal @transition, @observer_update.transition
    end
    
    def test_should_include_object_and_transition_in_args
      assert_equal [@record, @transition], @observer_update.args
    end
    
    def test_should_use_record_class_as_class
      assert_equal @model, @observer_update.class
    end
  end
  
  class MachineWithObserversTest < BaseTestCase
    def setup
      @model = new_model { include ActiveModel::Observing }
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :idling
      @machine.event :ignite
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
    end
    
    def test_should_call_all_transition_callback_permutations
      callbacks = [
        :before_ignite_from_parked_to_idling,
        :before_ignite_from_parked,
        :before_ignite_to_idling,
        :before_ignite,
        :before_transition_state_from_parked_to_idling,
        :before_transition_state_from_parked,
        :before_transition_state_to_idling,
        :before_transition_state,
        :before_transition
      ]
      
      observer = new_observer(@model) do
        callbacks.each do |callback|
          define_method(callback) do |*args|
            notifications << callback
          end
        end
      end
      
      instance = observer.instance
      
      @transition.perform
      assert_equal callbacks, instance.notifications
    end
    
    def test_should_call_no_transition_callbacks_when_observers_disabled
      return unless ::ActiveModel::VERSION::MAJOR >= 3 && ::ActiveModel::VERSION::MINOR >= 1
      
      callbacks = [
        :before_ignite,
        :before_transition
      ]
      
      observer = new_observer(@model) do
        callbacks.each do |callback|
          define_method(callback) do |*args|
            notifications << callback
          end
        end
      end
      
      instance = observer.instance
      
      @model.observers.disable(observer) do
        @transition.perform
      end
      
      assert_equal [], instance.notifications
    end
    
    def test_should_pass_record_and_transition_to_before_callbacks
      observer = new_observer(@model) do
        def before_transition(*args)
          notifications << args
        end
      end
      instance = observer.instance
      
      @transition.perform
      assert_equal [[@record, @transition]], instance.notifications
    end
    
    def test_should_pass_record_and_transition_to_after_callbacks
      observer = new_observer(@model) do
        def after_transition(*args)
          notifications << args
        end
      end
      instance = observer.instance
      
      @transition.perform
      assert_equal [[@record, @transition]], instance.notifications
    end
    
    def test_should_call_methods_outside_the_context_of_the_record
      observer = new_observer(@model) do
        def before_ignite(*args)
          notifications << self
        end
      end
      instance = observer.instance
      
      @transition.perform
      assert_equal [instance], instance.notifications
    end
    
    def test_should_support_nil_from_states
      callbacks = [
        :before_ignite_from_nil_to_idling,
        :before_ignite_from_nil,
        :before_transition_state_from_nil_to_idling,
        :before_transition_state_from_nil
      ]
      
      notified = false
      observer = new_observer(@model) do
        callbacks.each do |callback|
          define_method(callback) do |*args|
            notifications << callback
          end
        end
      end
      
      instance = observer.instance
      
      transition = StateMachine::Transition.new(@record, @machine, :ignite, nil, :idling)
      transition.perform
      assert_equal callbacks, instance.notifications
    end
    
    def test_should_support_nil_to_states
      callbacks = [
        :before_ignite_from_parked_to_nil,
        :before_ignite_to_nil,
        :before_transition_state_from_parked_to_nil,
        :before_transition_state_to_nil
      ]
      
      notified = false
      observer = new_observer(@model) do
        callbacks.each do |callback|
          define_method(callback) do |*args|
            notifications << callback
          end
        end
      end
      
      instance = observer.instance
      
      transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, nil)
      transition.perform
      assert_equal callbacks, instance.notifications
    end
  end
  
  class MachineWithNamespacedObserversTest < BaseTestCase
    def setup
      @model = new_model { include ActiveModel::Observing }
      @machine = StateMachine::Machine.new(@model, :state, :namespace => 'alarm')
      @machine.state :active, :off
      @machine.event :enable
      @record = @model.new(:state => 'off')
      @transition = StateMachine::Transition.new(@record, @machine, :enable, :off, :active)
    end
    
    def test_should_call_namespaced_before_event_method
      observer = new_observer(@model) do
        def before_enable_alarm(*args)
          notifications << args
        end
      end
      instance = observer.instance
      
      @transition.perform
      assert_equal [[@record, @transition]], instance.notifications
    end
    
    def test_should_call_namespaced_after_event_method
      observer = new_observer(@model) do
        def after_enable_alarm(*args)
          notifications << args
        end
      end
      instance = observer.instance
      
      @transition.perform
      assert_equal [[@record, @transition]], instance.notifications
    end
  end
  
  class MachineWithFailureCallbacksTest < BaseTestCase
    def setup
      @model = new_model { include ActiveModel::Observing }
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :idling
      @machine.event :ignite
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      
      @notifications = []
      
      # Create callbacks
      @machine.before_transition {false}
      @machine.after_failure {@notifications << :callback_after_failure}
      
      # Create observer callbacks
      observer = new_observer(@model) do
        def after_failure_to_ignite(*args)
          notifications << :observer_after_failure_ignite
        end
        
        def after_failure_to_transition(*args)
          notifications << :observer_after_failure_transition
        end
      end
      instance = observer.instance
      instance.notifications = @notifications
      
      @transition.perform
    end
    
    def test_should_invoke_callbacks_in_specific_order
      expected = [
        :callback_after_failure,
        :observer_after_failure_ignite,
        :observer_after_failure_transition
      ]
      
      assert_equal expected, @notifications
    end
  end
  
  class MachineWithMixedCallbacksTest < BaseTestCase
    def setup
      @model = new_model { include ActiveModel::Observing }
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :idling
      @machine.event :ignite
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      
      @notifications = []
      
      # Create callbacks
      @machine.before_transition {@notifications << :callback_before_transition}
      @machine.after_transition {@notifications << :callback_after_transition}
      @machine.around_transition {|block| @notifications << :callback_around_before_transition; block.call; @notifications << :callback_around_after_transition}
      
      # Create observer callbacks
      observer = new_observer(@model) do
        def before_ignite(*args)
          notifications << :observer_before_ignite
        end
        
        def before_transition(*args)
          notifications << :observer_before_transition
        end
        
        def after_ignite(*args)
          notifications << :observer_after_ignite
        end
        
        def after_transition(*args)
          notifications << :observer_after_transition
        end
      end
      instance = observer.instance
      instance.notifications = @notifications
      
      @transition.perform
    end
    
    def test_should_invoke_callbacks_in_specific_order
      expected = [
        :callback_before_transition,
        :callback_around_before_transition,
        :observer_before_ignite,
        :observer_before_transition,
        :callback_around_after_transition,
        :callback_after_transition,
        :observer_after_ignite,
        :observer_after_transition
      ]
      
      assert_equal expected, @notifications
    end
  end
  
  class MachineWithInternationalizationTest < BaseTestCase
    def setup
      I18n.backend = I18n::Backend::Simple.new
      
      # Initialize the backend
      I18n.backend.translate(:en, 'activemodel.errors.messages.invalid_transition', :event => 'ignite', :value => 'idling')
      
      @model = new_model { include ActiveModel::Validations }
    end
    
    def test_should_use_defaults
      I18n.backend.store_translations(:en, {
        :activemodel => {:errors => {:messages => {:invalid_transition => 'cannot %{event}'}}}
      })
      
      machine = StateMachine::Machine.new(@model, :action => :save)
      machine.state :parked, :idling
      machine.event :ignite
      
      record = @model.new(:state => 'idling')
      
      machine.invalidate(record, :state, :invalid_transition, [[:event, 'ignite']])
      assert_equal ['State cannot ignite'], record.errors.full_messages
    end
    
    def test_should_allow_customized_error_key
      I18n.backend.store_translations(:en, {
        :activemodel => {:errors => {:messages => {:bad_transition => 'cannot %{event}'}}}
      })
      
      machine = StateMachine::Machine.new(@model, :action => :save, :messages => {:invalid_transition => :bad_transition})
      machine.state :parked, :idling
      
      record = @model.new
      record.state = 'idling'
      
      machine.invalidate(record, :state, :invalid_transition, [[:event, 'ignite']])
      assert_equal ['State cannot ignite'], record.errors.full_messages
    end
    
    def test_should_allow_customized_error_string
      machine = StateMachine::Machine.new(@model, :action => :save, :messages => {:invalid_transition => 'cannot %{event}'})
      machine.state :parked, :idling
      
      record = @model.new(:state => 'idling')
      
      machine.invalidate(record, :state, :invalid_transition, [[:event, 'ignite']])
      assert_equal ['State cannot ignite'], record.errors.full_messages
    end
    
    def test_should_allow_customized_state_key_scoped_to_class_and_machine
      I18n.backend.store_translations(:en, {
        :activemodel => {:state_machines => {:'active_model_test/foo' => {:state => {:states => {:parked => 'shutdown'}}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked
      
      assert_equal 'shutdown', machine.state(:parked).human_name
    end
    
    def test_should_allow_customized_state_key_scoped_to_class
      I18n.backend.store_translations(:en, {
        :activemodel => {:state_machines => {:'active_model_test/foo' => {:states => {:parked => 'shutdown'}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked
      
      assert_equal 'shutdown', machine.state(:parked).human_name
    end
    
    def test_should_allow_customized_state_key_scoped_to_machine
      I18n.backend.store_translations(:en, {
        :activemodel => {:state_machines => {:state => {:states => {:parked => 'shutdown'}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked
      
      assert_equal 'shutdown', machine.state(:parked).human_name
    end
    
    def test_should_allow_customized_state_key_unscoped
      I18n.backend.store_translations(:en, {
        :activemodel => {:state_machines => {:states => {:parked => 'shutdown'}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked
      
      assert_equal 'shutdown', machine.state(:parked).human_name
    end
    
    def test_should_support_nil_state_key
      I18n.backend.store_translations(:en, {
        :activemodel => {:state_machines => {:states => {:nil => 'empty'}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      
      assert_equal 'empty', machine.state(nil).human_name
    end
    
    def test_should_allow_customized_event_key_scoped_to_class_and_machine
      I18n.backend.store_translations(:en, {
        :activemodel => {:state_machines => {:'active_model_test/foo' => {:state => {:events => {:park => 'stop'}}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.event :park
      
      assert_equal 'stop', machine.event(:park).human_name
    end
    
    def test_should_allow_customized_event_key_scoped_to_class
      I18n.backend.store_translations(:en, {
        :activemodel => {:state_machines => {:'active_model_test/foo' => {:events => {:park => 'stop'}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.event :park
      
      assert_equal 'stop', machine.event(:park).human_name
    end
    
    def test_should_allow_customized_event_key_scoped_to_machine
      I18n.backend.store_translations(:en, {
        :activemodel => {:state_machines => {:state => {:events => {:park => 'stop'}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.event :park
      
      assert_equal 'stop', machine.event(:park).human_name
    end
    
    def test_should_allow_customized_event_key_unscoped
      I18n.backend.store_translations(:en, {
        :activemodel => {:state_machines => {:events => {:park => 'stop'}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.event :park
      
      assert_equal 'stop', machine.event(:park).human_name
    end
    
    def test_should_only_add_locale_once_in_load_path
      assert_equal 1, I18n.load_path.select {|path| path =~ %r{active_model/locale\.rb$}}.length
      
      # Create another ActiveModel model that will triger the i18n feature
      new_model
      
      assert_equal 1, I18n.load_path.select {|path| path =~ %r{active_model/locale\.rb$}}.length
    end
    
    def test_should_add_locale_to_beginning_of_load_path
      @original_load_path = I18n.load_path
      I18n.backend = I18n::Backend::Simple.new
      
      app_locale = File.dirname(__FILE__) + '/../../files/en.yml'
      default_locale = File.dirname(__FILE__) + '/../../../lib/state_machine/integrations/active_model/locale.rb'
      I18n.load_path = [app_locale]
      
      StateMachine::Machine.new(@model)
      
      assert_equal [default_locale, app_locale].map {|path| File.expand_path(path)}, I18n.load_path.map {|path| File.expand_path(path)}
    ensure
      I18n.load_path = @original_load_path
    end
    
    def test_should_prefer_other_locales_first
      @original_load_path = I18n.load_path
      I18n.backend = I18n::Backend::Simple.new
      I18n.load_path = [File.dirname(__FILE__) + '/../../files/en.yml']
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked, :idling
      machine.event :ignite
      
      record = @model.new(:state => 'idling')
      
      machine.invalidate(record, :state, :invalid_transition, [[:event, 'ignite']])
      assert_equal ['State cannot ignite'], record.errors.full_messages
    ensure
      I18n.load_path = @original_load_path
    end
  end
end
