require File.expand_path(File.dirname(__FILE__) + '/../../test_helper')

require 'mongoid'
require 'mongoid/version'

# Establish database connection
Mongoid.configure do |config|
  config.master = Mongo::Connection.new('127.0.0.1', 27017, :slave_ok => true).db('test')
end

module MongoidTest
  class BaseTestCase < Test::Unit::TestCase
    def default_test
    end
    
    protected
      # Creates a new Mongoid model (and the associated table)
      def new_model(table_name = :foo, &block)
        
        model = Class.new do
          (class << self; self; end).class_eval do
            define_method(:name) { "MongoidTest::#{table_name.to_s.capitalize}" }
            define_method(:to_s) { name }
          end
        end
        
        model.class_eval do
          include Mongoid::Document
          self.collection_name = table_name
          
          field :state, :type => String
        end
        model.class_eval(&block) if block_given?
        model.collection.remove
        model
      end
  end
  
  class IntegrationTest < BaseTestCase
    def test_should_have_an_integration_name
      assert_equal :mongoid, StateMachine::Integrations::Mongoid.integration_name
    end
    
    def test_should_be_available
      assert StateMachine::Integrations::Mongoid.available?
    end
    
    def test_should_match_if_class_includes_mongoid
      assert StateMachine::Integrations::Mongoid.matches?(new_model)
    end
    
    def test_should_not_match_if_class_does_not_include_mongoid
      assert !StateMachine::Integrations::Mongoid.matches?(Class.new)
    end
    
    def test_should_have_defaults
      assert_equal e = {:action => :save}, StateMachine::Integrations::Mongoid.defaults
    end
    
    def test_should_have_a_locale_path
      assert_not_nil StateMachine::Integrations::Mongoid.locale_path
    end
  end
  
  class MachineWithoutFieldTest < BaseTestCase
    def setup
      @model = new_model
      StateMachine::Machine.new(@model, :status)
    end
    
    def test_should_define_field_with_string_type
      field = @model.fields['status']
      assert_not_nil field
      assert_equal String, field.type
    end
  end
  
  class MachineWithFieldTest < BaseTestCase
    def setup
      @model = new_model do
        field :status, :type => Integer
      end
      StateMachine::Machine.new(@model, :status)
    end
    
    def test_should_not_redefine_field
      field = @model.fields['status']
      assert_not_nil field
      assert_equal Integer, field.type
    end
  end
  
  class MachineByDefaultTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
    end
    
    def test_should_use_save_as_action
      assert_equal :save, @machine.action
    end
    
    def test_should_create_notifier_before_callback
      assert_equal 1, @machine.callbacks[:before].size
    end
    
    def test_should_create_notifier_after_callback
      assert_equal 1, @machine.callbacks[:after].size
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
      @model = new_model do
        attr_accessor :value
      end
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
    end
    
    def test_should_set_initial_state_on_created_object
      record = @model.new
      assert_equal 'parked', record.state
    end
    
    def test_should_set_initial_state_with_nil_attributes
      record = @model.new(nil)
      assert_equal 'parked', record.state
    end
    
    def test_should_still_set_attributes
      record = @model.new(:value => 1)
      assert_equal 1, record.value
    end
    
    def test_should_still_allow_initialize_blocks
      block_args = nil
      record = @model.new do |*args|
        block_args = args
      end
      
      assert_equal [record], block_args
    end
    
    def test_should_set_attributes_prior_to_initialize_block
      state = nil
      record = @model.new do |record|
        state = record.state
      end
      
      assert_equal 'parked', state
    end
    
    def test_should_set_attributes_prior_to_after_initialize_hook
      state = nil
      @model.after_initialize do |record|
        state = record.state
      end
      @model.new
      assert_equal 'parked', state
    end
    
    def test_should_set_initial_state_before_setting_attributes
      @model.class_eval do
        attr_accessor :state_during_setter
        
        define_method(:value=) do |value|
          self.state_during_setter = state
        end
      end
      
      record = @model.new(:value => 1)
      assert_equal 'parked', record.state_during_setter
    end
    
    def test_should_not_set_initial_state_after_already_initialized
      record = @model.new(:value => 1)
      assert_equal 'parked', record.state
      
      record.state = 'idling'
      record.process({})
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database
      @machine.state :idling
      
      record = @model.find(@model.create(:state => 'idling').id)
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database_with_nil_state
      @machine.state nil
      
      record = @model.find(@model.create(:state => nil).id)
      assert_nil record.state
    end
  end
  
  class MachineWithDynamicInitialStateTest < BaseTestCase
    def setup
      @model = new_model do
        attr_accessor :value
      end
      @machine = StateMachine::Machine.new(@model, :initial => lambda {|object| :parked})
      @machine.state :parked
    end
    
    def test_should_set_initial_state_on_created_object
      record = @model.new
      assert_equal 'parked', record.state
    end
    
    def test_should_still_set_attributes
      record = @model.new(:value => 1)
      assert_equal 1, record.value
    end
    
    def test_should_still_allow_initialize_blocks
      block_args = nil
      record = @model.new do |*args|
        block_args = args
      end
      
      assert_equal [record], block_args
    end
    
    def test_should_set_attributes_prior_to_initialize_block
      state = nil
      record = @model.new do |record|
        state = record.state
      end
      
      assert_equal 'parked', state
    end
    
    def test_should_set_attributes_prior_to_after_initialize_hook
      state = nil
      @model.after_initialize do |record|
        state = record.state
      end
      @model.new
      assert_equal 'parked', state
    end
    
    def test_should_set_initial_state_after_setting_attributes
      @model.class_eval do
        attr_accessor :state_during_setter
        
        define_method(:value=) do |value|
          self.state_during_setter = state || 'nil'
        end
      end
      
      record = @model.new(:value => 1)
      assert_equal 'nil', record.state_during_setter
    end
    
    def test_should_not_set_initial_state_after_already_initialized
      record = @model.new(:value => 1)
      assert_equal 'parked', record.state
      
      record.state = 'idling'
      record.process({})
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database
      @machine.state :idling
      
      record = @model.find(@model.create(:state => 'idling').id)
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database_with_nil_state
      @machine.state nil
      
      record = @model.find(@model.create(:state => nil).id)
      assert_nil record.state
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
  
  class MachineWithColumnDefaultTest < BaseTestCase
    def setup
      @model = new_model do
        field :status, :type => String, :default => 'idling'
      end
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
      @record = @model.new
    end
    
    def test_should_use_machine_default
      assert_equal 'parked', @record.status
    end
  end
  
  class MachineWithConflictingPredicateTest < BaseTestCase
    def setup
      @model = new_model do
        def state?(*args)
          true
        end
      end
      
      @machine = StateMachine::Machine.new(@model)
      @record = @model.new
    end
    
    def test_should_not_define_attribute_predicate
      assert @record.state?
    end
  end
  
  class MachineWithConflictingStateNameTest < BaseTestCase
    def setup
      require 'stringio'
      @original_stderr, $stderr = $stderr, StringIO.new
      
      @model = new_model
    end
    
    def test_should_output_warning_with_same_machine_name
      @machine = StateMachine::Machine.new(@model)
      @machine.state :state
      
      assert_match /^Instance method "state\?" is already defined in .*, use generic helper instead.*\n$/, $stderr.string
    end
    
    def test_should_output_warning_with_same_machine_attribute
      @machine = StateMachine::Machine.new(@model, :public_state, :attribute => :state)
      @machine.state :state
      
      assert_match /^Instance method "state\?" is already defined in .*, use generic helper instead.*\n$/, $stderr.string
    end
    
    def teardown
      $stderr = @original_stderr
    end
  end
  
  class MachineWithColumnStateAttributeTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.other_states(:idling)
      
      @record = @model.new
    end
    
    def test_should_not_override_the_column_reader
      @record[:state] = 'parked'
      assert_equal 'parked', @record.state
    end
    
    def test_should_not_override_the_column_writer
      @record.state = 'parked'
      assert_equal 'parked', @record[:state]
    end
    
    def test_should_have_an_attribute_predicate
      assert @record.respond_to?(:state?)
    end
    
    def test_should_test_for_existence_on_predicate_without_parameters
      assert @record.state?
      
      @record.state = nil
      assert !@record.state?
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
  
  class MachineWithNonColumnStateAttributeUndefinedTest < BaseTestCase
    def setup
      @model = new_model do
        def initialize
          # Skip attribute initialization
          @initialized_state_machines = true
          super
        end
      end
      
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
      @machine.other_states(:idling)
      @record = @model.new
    end
    
    def test_should_define_a_new_key_for_the_attribute
      assert_not_nil @model.fields['status']
    end
    
    def test_should_define_a_reader_attribute_for_the_attribute
      assert @record.respond_to?(:status)
    end
    
    def test_should_define_a_writer_attribute_for_the_attribute
      assert @record.respond_to?(:status=)
    end
    
    def test_should_define_an_attribute_predicate
      assert @record.respond_to?(:status?)
    end
  end
  
  class MachineWithNonColumnStateAttributeDefinedTest < BaseTestCase
    def setup
      @model = new_model do
        def status
          self['status']
        end
        
        def status=(value)
          self['status'] = value
        end
      end
      
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
      @machine.other_states(:idling)
      @record = @model.new
    end
    
    def test_should_return_false_for_predicate_if_does_not_match_current_value
      assert !@record.status?(:idling)
    end
    
    def test_should_return_true_for_predicate_if_matches_current_value
      assert @record.status?(:parked)
    end
    
    def test_should_raise_exception_for_predicate_if_invalid_state_specified
      assert_raise(IndexError) { @record.status?(:invalid) }
    end
    
    def test_should_set_initial_state_on_created_object
      assert_equal 'parked', @record.status
    end
  end
  
  class MachineWithAliasedAttributeTest < BaseTestCase
    def setup
      @model = new_model do
        alias_attribute :vehicle_status, :state
      end
      
      @machine = StateMachine::Machine.new(@model, :status, :attribute => :vehicle_status)
      @machine.state :parked
      
      @record = @model.new
    end
    
    def test_should_check_custom_attribute_for_predicate
      @record.vehicle_status = nil
      assert !@record.status?(:parked)
      
      @record.vehicle_status = 'parked'
      assert @record.status?(:parked)
    end
  end
  
  class MachineWithCustomAttributeTest < BaseTestCase
    def setup
      require 'stringio'
      @original_stderr, $stderr = $stderr, StringIO.new
      
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :public_state, :attribute => :state)
      @record = @model.new
    end
    
    def test_should_not_delegate_attribute_predicate_with_different_attribute
      assert_raise(ArgumentError) { @record.public_state? }
    end
    
    def teardown
      $stderr = @original_stderr
    end
  end
  
  class MachineWithInitializedStateTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.state :idling
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
      record = silence_warnings { @model.new(:state => 'idling') }
      assert_equal 'idling', record.state
    end
    
    def test_should_use_default_state_if_protected
      @model.class_eval do
        attr_protected :state
      end
      
      record = @model.new(:state => 'idling')
      assert_equal 'parked', record.state
    end
  end
  
  class MachineMultipleTest < BaseTestCase
    def setup
      @model = new_model do
        field :status, :type => String, :default => 'idling'
      end
      @state_machine = StateMachine::Machine.new(@model, :initial => :parked)
      @status_machine = StateMachine::Machine.new(@model, :status, :initial => :idling)
    end
    
    def test_should_should_initialize_each_state
      record = @model.new
      assert_equal 'parked', record.state
      assert_equal 'idling', record.status
    end
  end
  
  class MachineWithLoopbackTest < BaseTestCase
    def setup
      @model = new_model do
        field :updated_at, :type => Time
        
        before_update do |record|
          record.updated_at = Time.now
        end
      end
      
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.event :park
      
      @record = @model.create(:updated_at => Time.now - 1)
      @transition = StateMachine::Transition.new(@record, @machine, :park, :parked, :parked)
      
      @timestamp = @record.updated_at
      @transition.perform
    end
    
    def test_should_update_record
      assert_not_equal @timestamp, @record.updated_at
    end
  end
  
  class MachineWithDirtyAttributesTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.event :ignite
      @machine.state :idling
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @transition.perform(false)
    end
    
    def test_should_include_state_in_changed_attributes
      assert_equal %w(state), @record.changed
    end
    
    def test_should_track_attribute_change
      assert_equal %w(parked idling), @record.changes['state']
    end
    
    def test_should_not_reset_changes_on_multiple_transitions
      transition = StateMachine::Transition.new(@record, @machine, :ignite, :idling, :idling)
      transition.perform(false)
      
      assert_equal %w(parked idling), @record.changes['state']
    end
    
    def test_should_not_have_changes_when_loaded_from_database
      record = @model.find(@record.id)
      assert !record.changed?
    end
  end
  
  class MachineWithDirtyAttributesDuringLoopbackTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.event :park
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :park, :parked, :parked)
      @transition.perform(false)
    end
    
    if ::Mongoid::VERSION =~ /^2\.0\./
      def test_should_include_state_in_changed_attributes
        assert_equal %w(state), @record.changed
      end
      
      def test_should_not_track_attribute_changes
        assert_equal %w(parked parked), @record.send(:attribute_change, 'state')
      end
    else
      def test_should_not_include_state_in_changed_attributes
        assert_equal [], @record.changed
      end
      
      def test_should_not_track_attribute_changes
        assert_equal nil, @record.send(:attribute_change, 'state')
      end
    end
  end
  
  class MachineWithDirtyAttributesAndCustomAttributeTest < BaseTestCase
    def setup
      @model = new_model do
        field :status, :type => String, :default => 'idling'
      end
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
      @machine.event :ignite
      @machine.state :idling
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @transition.perform(false)
    end
    
    def test_should_include_state_in_changed_attributes
      assert_equal %w(status), @record.changed
    end
    
    def test_should_track_attribute_change
      assert_equal %w(parked idling), @record.changes['status']
    end
    
    def test_should_not_reset_changes_on_multiple_transitions
      transition = StateMachine::Transition.new(@record, @machine, :ignite, :idling, :idling)
      transition.perform(false)
      
      assert_equal %w(parked idling), @record.changes['status']
    end
  end
  
  class MachineWithDirtyAttributeAndCustomAttributesDuringLoopbackTest < BaseTestCase
    def setup
      @model = new_model do
        field :status, :type => String, :default => 'idling'
      end
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
      @machine.event :park
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :park, :parked, :parked)
      @transition.perform(false)
    end
    
    if ::Mongoid::VERSION =~ /^2\.0\./
      def test_should_include_state_in_changed_attributes
        assert_equal %w(status), @record.changed
      end
      
      def test_should_track_attribute_changes
        assert_equal %w(parked parked), @record.send(:attribute_change, 'status')
      end
    else
      def test_should_include_state_in_changed_attributes
        assert_equal [], @record.changed
      end
      
      def test_should_track_attribute_changes
        assert_equal nil, @record.send(:attribute_change, 'status')
      end
    end
  end
  
  class MachineWithDirtyAttributeAndStateEventsTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.event :ignite
      
      @record = @model.create
      @record.state_event = 'ignite'
    end
    
    if ::Mongoid::VERSION =~ /^2\.0\./
      def test_should_include_state_in_changed_attributes
        assert_equal %w(state), @record.changed
      end
      
      def test_should_track_attribute_change
        assert_equal %w(parked parked), @record.send(:attribute_change, 'state')
      end
      
      def test_should_not_reset_changes_on_multiple_changes
        @record.state_event = 'ignite'
        assert_equal %w(parked parked), @record.send(:attribute_change, 'state')
      end
      
      def test_should_not_include_state_in_changed_attributes_if_nil
        @record = @model.create
        @record.state_event = nil
        
        assert_equal [], @record.changed
      end
    else
      def test_should_not_include_state_in_changed_attributes
        assert_equal [], @record.changed
      end
      
      def test_should_not_track_attribute_change
        assert_equal nil, @record.send(:attribute_change, 'state')
      end
    end
  end
  
  class MachineWithCallbacksTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
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
    
    def test_should_run_after_callbacks_if_model_callback_added_prior_to_state_machine_definition
      model = new_model do
        after_save { nil }
      end
      machine = StateMachine::Machine.new(model, :initial => :parked)
      machine.other_states :idling
      machine.event :ignite
      after_called = false
      machine.after_transition {after_called = true}
      
      record = model.new(:state => 'parked')
      transition = StateMachine::Transition.new(record, machine, :ignite, :parked, :idling)
      transition.perform
      assert_equal true, after_called
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
      @machine = StateMachine::Machine.new(@model)
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
    
    def test_should_not_run_action
      assert @record.new_record?
    end
    
    def test_should_not_run_further_callbacks
      assert_equal [:before_1], @callbacks
    end
  end
  
  class MachineWithFailedActionTest < BaseTestCase
    def setup
      @model = new_model do
        validates_numericality_of :state
      end
      
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :idling
      @machine.event :ignite
      
      @callbacks = []
      @machine.before_transition {@callbacks << :before}
      @machine.after_transition {@callbacks << :after}
      @machine.after_failure {@callbacks << :after_failure}
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
    
    def test_should_not_save_record
      assert @record.new_record?
    end
    
    def test_should_run_before_callbacks_and_after_callbacks_with_failures
      assert_equal [:before, :around_before, :after_failure], @callbacks
    end
  end
  
  class MachineWithFailedAfterCallbacksTest < BaseTestCase
     def setup
      @callbacks = []
      
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
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
    
    def test_should_save_record
      assert !@record.new_record?
    end
    
    def test_should_not_run_further_after_callbacks
      assert_equal [:around_before, :around_after, :after_1], @callbacks
    end
  end
  
  class MachineWithValidationsTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked
      
      @record = @model.new
    end
    
    def test_should_invalidate_using_errors
      I18n.backend = I18n::Backend::Simple.new if Object.const_defined?(:ActiveModel)
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
      @model = new_model do
        alias_attribute :status, :state
      end
      
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
      @model = new_model
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
        attr_accessor :seatbealt
      end
      
      @machine = StateMachine::Machine.new(@model)
      @machine.state :first_gear do
        validates_presence_of :seatbelt, :key => :first_gear
      end
      @machine.state :second_gear do
        validates_presence_of :seatbelt, :key => :second_gear
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
  
  class MachineWithEventAttributesOnValidationTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.event :ignite do
        transition :parked => :idling
      end
      
      @record = @model.new
      @record.state = 'parked'
      @record.state_event = 'ignite'
    end
    
    def test_should_fail_if_event_is_invalid
      @record.state_event = 'invalid'
      assert !@record.valid?
      assert_equal ['State event is invalid'], @record.errors.full_messages
    end
    
    def test_should_fail_if_event_has_no_transition
      @record.state = 'idling'
      assert !@record.valid?
      assert_equal ['State event cannot transition when idling'], @record.errors.full_messages
    end
    
    def test_should_be_successful_if_event_has_transition
      assert @record.valid?
    end
    
    def test_should_run_before_callbacks
      ran_callback = false
      @machine.before_transition { ran_callback = true }
      
      @record.valid?
      assert ran_callback
    end
    
    def test_should_run_around_callbacks_before_yield
      ran_callback = false
      @machine.around_transition {|block| ran_callback = true; block.call }
      
      @record.valid?
      assert ran_callback
    end
    
    def test_should_persist_new_state
      @record.valid?
      assert_equal 'idling', @record.state
    end
    
    def test_should_not_run_after_callbacks
      ran_callback = false
      @machine.after_transition { ran_callback = true }
      
      @record.valid?
      assert !ran_callback
    end
    
    def test_should_not_run_after_callbacks_with_failures_disabled_if_validation_fails
      @model.class_eval do
        attr_accessor :seatbelt
        validates_presence_of :seatbelt
      end
      
      ran_callback = false
      @machine.after_transition { ran_callback = true }
      
      @record.valid?
      assert !ran_callback
    end
    
    def test_should_not_run_around_callbacks_after_yield
      ran_callback = false
      @machine.around_transition {|block| block.call; ran_callback = true }
      
      @record.valid?
      assert !ran_callback
    end
    
    def test_should_not_run_around_callbacks_after_yield_with_failures_disabled_if_validation_fails
      @model.class_eval do
        attr_accessor :seatbelt
        validates_presence_of :seatbelt
      end
      
      ran_callback = false
      @machine.around_transition {|block| block.call; ran_callback = true }
      
      @record.valid?
      assert !ran_callback
    end
    
    def test_should_run_failure_callbacks_if_validation_fails
      @model.class_eval do
        attr_accessor :seatbelt
        validates_presence_of :seatbelt
      end
      
      ran_callback = false
      @machine.after_failure { ran_callback = true }
      
      @record.valid?
      assert ran_callback
    end
  end
  
  class MachineWithEventAttributesOnSaveTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.event :ignite do
        transition :parked => :idling
      end
      
      @record = @model.new
      @record.state = 'parked'
      @record.state_event = 'ignite'
    end
    
    def test_should_fail_if_event_is_invalid
      @record.state_event = 'invalid'
      assert_equal false, @record.save
    end
    
    def test_should_fail_if_event_has_no_transition
      @record.state = 'idling'
      assert_equal false, @record.save
    end
    
    def test_should_be_successful_if_event_has_transition
      assert_equal true, @record.save
    end
    
    def test_should_run_before_callbacks
      ran_callback = false
      @machine.before_transition { ran_callback = true }
      
      @record.save
      assert ran_callback
    end
    
    def test_should_run_before_callbacks_once
      before_count = 0
      @machine.before_transition { before_count += 1 }
      
      @record.save
      assert_equal 1, before_count
    end
    
    def test_should_run_around_callbacks_before_yield
      ran_callback = false
      @machine.around_transition {|block| ran_callback = true; block.call }
      
      @record.save
      assert ran_callback
    end
    
    def test_should_run_around_callbacks_before_yield_once
      around_before_count = 0
      @machine.around_transition {|block| around_before_count += 1; block.call }
      
      @record.save
      assert_equal 1, around_before_count
    end
    
    def test_should_persist_new_state
      @record.save
      assert_equal 'idling', @record.state
    end
    
    def test_should_run_after_callbacks
      ran_callback = false
      @machine.after_transition { ran_callback = true }
      
      @record.save
      assert ran_callback
    end
    
    def test_should_not_run_after_callbacks_with_failures_disabled_if_fails
      @model.class_eval do
        validates_numericality_of :state
      end
      
      ran_callback = false
      @machine.after_transition { ran_callback = true }
      
      begin; @record.save; rescue; end
      assert !ran_callback
    end
    
    def test_should_run_failure_callbacks__if_fails
      @model.class_eval do
        validates_numericality_of :state
      end
      
      ran_callback = false
      @machine.after_failure { ran_callback = true }
      
      begin; @record.save; rescue; end
      assert ran_callback
    end
    
    def test_should_not_run_around_callbacks_with_failures_disabled_if_fails
      @model.class_eval do
        validates_numericality_of :state
      end
      
      ran_callback = false
      @machine.around_transition {|block| block.call; ran_callback = true }
      
      begin; @record.save; rescue; end
      assert !ran_callback
    end
    
    def test_should_run_around_callbacks_after_yield
      ran_callback = false
      @machine.around_transition {|block| block.call; ran_callback = true }
      
      @record.save
      assert ran_callback
    end
  end
  
  class MachineWithEventAttributesOnSaveBangTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.event :ignite do
        transition :parked => :idling
      end
      
      @record = @model.new
      @record.state = 'parked'
      @record.state_event = 'ignite'
    end
    
    def test_should_fail_if_event_is_invalid
      @record.state_event = 'invalid'
      assert_raise(Mongoid::Errors::Validations) { @record.save! }
    end
    
    def test_should_fail_if_event_has_no_transition
      @record.state = 'idling'
      assert_raise(Mongoid::Errors::Validations) { @record.save! }
    end
    
    def test_should_be_successful_if_event_has_transition
      assert_equal true, @record.save!
    end
    
    def test_should_run_before_callbacks
      ran_callback = false
      @machine.before_transition { ran_callback = true }
      
      @record.save!
      assert ran_callback
    end
    
    def test_should_run_before_callbacks_once
      before_count = 0
      @machine.before_transition { before_count += 1 }
      
      @record.save!
      assert_equal 1, before_count
    end
    
    def test_should_run_around_callbacks_before_yield
      ran_callback = false
      @machine.around_transition {|block| ran_callback = true; block.call }
      
      @record.save!
      assert ran_callback
    end
    
    def test_should_run_around_callbacks_before_yield_once
      around_before_count = 0
      @machine.around_transition {|block| around_before_count += 1; block.call }
      
      @record.save!
      assert_equal 1, around_before_count
    end
    
    def test_should_persist_new_state
      @record.save!
      assert_equal 'idling', @record.state
    end
    
    def test_should_persist_new_state
      @record.save!
      assert_equal 'idling', @record.state
    end
    
    def test_should_run_after_callbacks
      ran_callback = false
      @machine.after_transition { ran_callback = true }
      
      @record.save!
      assert ran_callback
    end
    
    def test_should_run_around_callbacks_after_yield
      ran_callback = false
      @machine.around_transition {|block| block.call; ran_callback = true }
      
      @record.save!
      assert ran_callback
    end
  end
  
  class MachineWithEventAttributesOnCustomActionTest < BaseTestCase
    def setup
      @superclass = new_model do
        def persist
          upsert
        end
      end
      @model = Class.new(@superclass)
      @machine = StateMachine::Machine.new(@model, :action => :persist)
      @machine.event :ignite do
        transition :parked => :idling
      end
      
      @record = @model.new
      @record.state = 'parked'
      @record.state_event = 'ignite'
    end
    
    def test_should_not_transition_on_valid?
      @record.valid?
      assert_equal 'parked', @record.state
    end
    
    def test_should_not_transition_on_save
      @record.save
      assert_equal 'parked', @record.state
    end
    
    def test_should_not_transition_on_save!
      @record.save!
      assert_equal 'parked', @record.state
    end
    
    def test_should_transition_on_custom_action
      @record.persist
      assert_equal 'idling', @record.state
    end
  end
  
  class MachineWithScopesTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :first_gear
      @machine.state :idling, :value => lambda {'idling'}
    end
    
    def test_should_create_singular_with_scope
      assert @model.respond_to?(:with_state)
    end
    
    def test_should_only_include_records_with_state_in_singular_with_scope
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [parked], @model.with_state(:parked).to_a
    end
    
    def test_should_create_plural_with_scope
      assert @model.respond_to?(:with_states)
    end
    
    def test_should_only_include_records_with_states_in_plural_with_scope
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [parked, idling], @model.with_states(:parked, :idling).to_a
    end
    
    def test_should_allow_lookup_by_string_name
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [parked, idling], @model.with_states('parked', 'idling').to_a
    end
    
    def test_should_create_singular_without_scope
      assert @model.respond_to?(:without_state)
    end
    
    def test_should_only_include_records_without_state_in_singular_without_scope
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [parked], @model.without_state(:idling).to_a
    end
    
    def test_should_create_plural_without_scope
      assert @model.respond_to?(:without_states)
    end
    
    def test_should_only_include_records_without_states_in_plural_without_scope
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      first_gear = @model.create :state => 'first_gear'
      
      assert_equal [parked, idling], @model.without_states(:first_gear).to_a
    end
    
    def test_should_allow_chaining_scopes
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [idling], @model.without_state(:parked).with_state(:idling).all
    end
  end
  
  class MachineWithScopesAndOwnerSubclassTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :state)
      
      MongoidTest.const_set('Foo', @model)
      
      @subclass = Class.new(@model) do
        def self.name
          'MongoidTest::SubFoo'
        end
      end
      @subclass_machine = @subclass.state_machine(:state) {}
      @subclass_machine.state :parked, :idling, :first_gear
      
      MongoidTest.const_set('SubFoo', @subclass)
    end
    
    def test_should_only_include_records_with_subclass_states_in_with_scope
      parked = @subclass.create :state => 'parked'
      idling = @subclass.create :state => 'idling'
      
      assert_equal [parked, idling], @subclass.with_states(:parked, :idling).to_a
    end
    
    def test_should_only_include_records_without_subclass_states_in_without_scope
      parked = @subclass.create :state => 'parked'
      idling = @subclass.create :state => 'idling'
      first_gear = @subclass.create :state => 'first_gear'
      
      assert_equal [parked, idling], @subclass.without_states(:first_gear).to_a
    end
    
    def teardown
      MongoidTest.send(:remove_const, 'SubFoo')
      MongoidTest.send(:remove_const, 'Foo')
    end
  end
  
  class MachineWithComplexPluralizationScopesTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :status)
    end
    
    def test_should_create_singular_with_scope
      assert @model.respond_to?(:with_status)
    end
    
    def test_should_create_plural_with_scope
      assert @model.respond_to?(:with_statuses)
    end
  end
  
  class MachineWithDefaultScope < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.state :idling
      
      @model.class_eval do
        default_scope with_state(:parked, :idling)
      end
    end
    
    def test_should_set_initial_state_on_created_object
      object = @model.new
      assert_equal 'parked', object.state
    end
  end
  
  class MachineWithInternationalizationTest < BaseTestCase
    def setup
      I18n.backend = I18n::Backend::Simple.new
      
      # Initialize the backend
      StateMachine::Machine.new(new_model)
      I18n.backend.translate(:en, 'mongoid.errors.messages.invalid_transition', :event => 'ignite', :value => 'idling')
      
      @model = new_model
    end
    
    def test_should_use_defaults
      I18n.backend.store_translations(:en, {
        :mongoid => {:errors => {:messages => {:invalid_transition => 'cannot %{event}'}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked, :idling
      machine.event :ignite
      
      record = @model.new(:state => 'idling')
      
      machine.invalidate(record, :state, :invalid_transition, [[:event, 'ignite']])
      assert_equal ['State cannot ignite'], record.errors.full_messages
    end
    
    def test_should_allow_customized_error_key
      I18n.backend.store_translations(:en, {
        :mongoid => {:errors => {:messages => {:bad_transition => 'cannot %{event}'}}}
      })
      
      machine = StateMachine::Machine.new(@model, :messages => {:invalid_transition => :bad_transition})
      machine.state :parked, :idling
      
      record = @model.new(:state => 'idling')
      
      machine.invalidate(record, :state, :invalid_transition, [[:event, 'ignite']])
      assert_equal ['State cannot ignite'], record.errors.full_messages
    end
    
    def test_should_allow_customized_error_string
      machine = StateMachine::Machine.new(@model, :messages => {:invalid_transition => 'cannot %{event}'})
      machine.state :parked, :idling
      
      record = @model.new(:state => 'idling')
      
      machine.invalidate(record, :state, :invalid_transition, [[:event, 'ignite']])
      assert_equal ['State cannot ignite'], record.errors.full_messages
    end
    
    def test_should_allow_customized_state_key_scoped_to_class_and_machine
      I18n.backend.store_translations(:en, {
        :mongoid => {:state_machines => {:'mongoid_test/foo' => {:state => {:states => {:parked => 'shutdown'}}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked
      
      assert_equal 'shutdown', machine.state(:parked).human_name
    end
    
    def test_should_allow_customized_state_key_scoped_to_class
      I18n.backend.store_translations(:en, {
        :mongoid => {:state_machines => {:'mongoid_test/foo' => {:states => {:parked => 'shutdown'}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked
      
      assert_equal 'shutdown', machine.state(:parked).human_name
    end
    
    def test_should_allow_customized_state_key_scoped_to_machine
      I18n.backend.store_translations(:en, {
        :mongoid => {:state_machines => {:state => {:states => {:parked => 'shutdown'}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked
      
      assert_equal 'shutdown', machine.state(:parked).human_name
    end
    
    def test_should_allow_customized_state_key_unscoped
      I18n.backend.store_translations(:en, {
        :mongoid => {:state_machines => {:states => {:parked => 'shutdown'}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.state :parked
      
      assert_equal 'shutdown', machine.state(:parked).human_name
    end
    
    def test_should_support_nil_state_key
      I18n.backend.store_translations(:en, {
        :mongoid => {:state_machines => {:states => {:nil => 'empty'}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      
      assert_equal 'empty', machine.state(nil).human_name
    end
    
    def test_should_allow_customized_event_key_scoped_to_class_and_machine
      I18n.backend.store_translations(:en, {
        :mongoid => {:state_machines => {:'mongoid_test/foo' => {:state => {:events => {:park => 'stop'}}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.event :park
      
      assert_equal 'stop', machine.event(:park).human_name
    end
    
    def test_should_allow_customized_event_key_scoped_to_class
      I18n.backend.store_translations(:en, {
        :mongoid => {:state_machines => {:'mongoid_test/foo' => {:events => {:park => 'stop'}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.event :park
      
      assert_equal 'stop', machine.event(:park).human_name
    end
    
    def test_should_allow_customized_event_key_scoped_to_machine
      I18n.backend.store_translations(:en, {
        :mongoid => {:state_machines => {:state => {:events => {:park => 'stop'}}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.event :park
      
      assert_equal 'stop', machine.event(:park).human_name
    end
    
    def test_should_allow_customized_event_key_unscoped
      I18n.backend.store_translations(:en, {
        :mongoid => {:state_machines => {:events => {:park => 'stop'}}}
      })
      
      machine = StateMachine::Machine.new(@model)
      machine.event :park
      
      assert_equal 'stop', machine.event(:park).human_name
    end
    
    def test_should_only_add_locale_once_in_load_path
      assert_equal 1, I18n.load_path.select {|path| path =~ %r{mongoid/locale\.rb$}}.length
      
      # Create another Mongoid model that will triger the i18n feature
      new_model
      
      assert_equal 1, I18n.load_path.select {|path| path =~ %r{mongoid/locale\.rb$}}.length
    end
    
    def test_should_add_locale_to_beginning_of_load_path
      @original_load_path = I18n.load_path
      I18n.backend = I18n::Backend::Simple.new
      
      app_locale = File.dirname(__FILE__) + '/../../files/en.yml'
      default_locale = File.dirname(__FILE__) + '/../../../lib/state_machine/integrations/mongoid/locale.rb'
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
      assert_equal ['State cannot transition'], record.errors.full_messages
    ensure
      I18n.load_path = @original_load_path
    end
  end
end
