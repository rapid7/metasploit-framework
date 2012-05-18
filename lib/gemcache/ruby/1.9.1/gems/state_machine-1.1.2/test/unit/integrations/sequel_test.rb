require File.expand_path(File.dirname(__FILE__) + '/../../test_helper')

require 'sequel'
require 'logger'

# Establish database connection
DB = Sequel.connect('sqlite:///', :loggers => [Logger.new("#{File.dirname(__FILE__)}/../../sequel.log")])

module SequelTest
  class BaseTestCase < Test::Unit::TestCase
    def default_test
    end
    
    protected
      # Creates a new Sequel model (and the associated table)
      def new_model(create_table = :foo, &block)
        table_name = create_table || :foo
        table_identifier = ::Sequel::SQL::Identifier.new(table_name)
        
        if !defined?(Sequel::VERSION) || Gem::Version.new(::Sequel::VERSION) <= Gem::Version.new('3.26.0')
          class << table_identifier
            alias_method :original_to_s, :to_s
            def to_s(*args); args.empty? ? inspect : original_to_s(*args); end
          end
        end
        
        DB.create_table!(table_identifier) do
          primary_key :id
          column :state, :string
        end if create_table
        model = Class.new(Sequel::Model(DB[table_identifier])) do
          self.raise_on_save_failure = false
          (class << self; self; end).class_eval do
            define_method(:name) { "SequelTest::#{table_name.to_s.capitalize}" }
          end
        end
        model.class_eval(&block) if block_given?
        model
      end
  end
  
  class IntegrationTest < BaseTestCase
    def test_should_have_an_integration_name
      assert_equal :sequel, StateMachine::Integrations::Sequel.integration_name
    end
    
    def test_should_be_available
      assert StateMachine::Integrations::Sequel.available?
    end
    
    def test_should_match_if_class_inherits_from_sequel
      assert StateMachine::Integrations::Sequel.matches?(new_model)
    end
    
    def test_should_not_match_if_class_does_not_inherit_from_sequel
      assert !StateMachine::Integrations::Sequel.matches?(Class.new)
    end
    
    def test_should_have_defaults
      assert_equal e = {:action => :save}, StateMachine::Integrations::Sequel.defaults
    end
    
    def test_should_not_have_a_locale_path
      assert_nil StateMachine::Integrations::Sequel.locale_path
    end
  end
  
  class MachineWithoutDatabaseTest < BaseTestCase
    def setup
      @model = new_model(false)
    end
    
    def test_should_allow_machine_creation
      assert_nothing_raised { StateMachine::Machine.new(@model) }
    end
  end
  
  class MachineUnmigratedTest < BaseTestCase
    def setup
      @model = new_model(false)
    end
    
    def test_should_allow_machine_creation
      assert_nothing_raised { StateMachine::Machine.new(@model) }
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
      @model.class_eval do
        def set(hash)
          super(hash || {})
        end
      end
      
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
      @model.class_eval do
        define_method(:after_initialize) do
          state = self.state
        end
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
      record.set({})
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database
      @machine.state :idling
      
      record = @model[@model.create(:state => 'idling').id]
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database_with_nil_state
      @machine.state nil
      
      record = @model[@model.create(:state => nil).id]
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
    
    def test_should_not_have_any_changed_columns
      record = @model.new
      assert record.changed_columns.empty?
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
      @model.class_eval do
        define_method(:after_initialize) do
          state = self.state
        end
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
      record.set({})
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database
      @machine.state :idling
      
      record = @model[@model.create(:state => 'idling').id]
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database_with_nil_state
      @machine.state nil
      
      record = @model[@model.create(:state => nil).id]
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
      @model = new_model
      DB.alter_table :foo do
        add_column :status, :string, :default => 'idling'
      end
      @model.class_eval { get_db_schema(true) }
      
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
  
  class MachineWithColumnStateAttributeTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :initial => :parked)
      @machine.other_states(:idling)
      
      @record = @model.new
    end
    
    def test_should_not_override_the_column_reader
      record = @model.new
      record[:state] = 'parked'
      assert_equal 'parked', record.state
    end
    
    def test_should_not_override_the_column_writer
      record = @model.new
      record.state = 'parked'
      assert_equal 'parked', record[:state]
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
  
  class MachineWithNonColumnStateAttributeUndefinedTest < BaseTestCase
    def setup
      @model = new_model do
        # Prevent attempts to access the status field
        def method_missing(method, *args)
          super unless %w(status status=).include?(method.to_s)
        end
      end
      
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
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
  
  class MachineWithNonColumnStateAttributeDefinedTest < BaseTestCase
    def setup
      @model = new_model do
        attr_accessor :status
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
    
    def test_should_set_initial_state_on_created_object
      assert_equal 'parked', @record.status
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
      record = @model.new(:state => 'idling')
      assert_equal 'idling', record.state
    end
    
    def test_should_use_default_state_if_protected
      @model.class_eval do
        self.strict_param_setting = false
        set_restricted_columns :state
      end
      
      record = @model.new(:state => 'idling')
      assert_equal 'parked', record.state
    end
  end
  
  class MachineMultipleTest < BaseTestCase
    def setup
      @model = new_model
      DB.alter_table :foo do
        add_column :status, :string, :default => 'idling'
      end
      @model.class_eval { get_db_schema(true) }
      
      @state_machine = StateMachine::Machine.new(@model, :initial => :parked)
      @status_machine = StateMachine::Machine.new(@model, :status, :initial => :idling)
    end
    
    def test_should_should_initialize_each_state
      record = @model.new
      assert_equal 'parked', record.state
      assert_equal 'idling', record.status
    end
  end
  
  class MachineWithAliasedAttributeTest < BaseTestCase
    def setup
      @model = new_model do
        alias_method :vehicle_status, :state
        alias_method :vehicle_status=, :state=
      end
      
      @machine = StateMachine::Machine.new(@model, :status, :attribute => :vehicle_status)
      @machine.state :parked
      
      @record = @model.new
    end
    
    def test_should_add_validation_errors_to_custom_attribute
      @record.vehicle_status = 'invalid'
      
      assert !@record.valid?
      assert_equal ['is invalid'], @record.errors.on(:vehicle_status)
      
      @record.vehicle_status = 'parked'
      assert @record.valid?
    end
  end
  
  class MachineWithLoopbackTest < BaseTestCase
    def setup
      @model = new_model do
        # Simulate timestamps plugin
        define_method(:before_update) do
          changed_columns = self.changed_columns.dup
          
          super()
          self.updated_at = Time.now if changed_columns.any?
        end
      end
      
      DB.alter_table :foo do
        add_column :updated_at, :datetime
      end
      @model.class_eval { get_db_schema(true) }
      
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
      assert_equal [:state], @record.changed_columns
    end
    
    def test_should_not_have_changes_when_loaded_from_database
      record = @model[@record.id]
      assert record.changed_columns.empty?
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
    
    def test_should_include_state_in_changed_attributes
      assert_equal [:state], @record.changed_columns
    end
  end
  
  class MachineWithDirtyAttributesAndCustomAttributeTest < BaseTestCase
    def setup
      @model = new_model
      DB.alter_table :foo do
        add_column :status, :string, :default => 'idling'
      end
      @model.class_eval { get_db_schema(true) }
      
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
      @machine.event :ignite
      @machine.state :idling
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @transition.perform(false)
    end
    
    def test_should_include_state_in_changed_attributes
      assert_equal [:status], @record.changed_columns
    end
  end
  
  class MachineWithDirtyAttributeAndCustomAttributesDuringLoopbackTest < BaseTestCase
    def setup
      @model = new_model
      DB.alter_table :foo do
        add_column :status, :string, :default => 'idling'
      end
      @model.class_eval { get_db_schema(true) }
      
      @machine = StateMachine::Machine.new(@model, :status, :initial => :parked)
      @machine.event :park
      
      @record = @model.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :park, :parked, :parked)
      @transition.perform(false)
    end
    
    def test_should_include_state_in_changed_attributes
      assert_equal [:status], @record.changed_columns
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
    
    def test_should_include_state_in_changed_attributes
      assert_equal [:state], @record.changed_columns
    end
    
    def test_should_not_include_state_in_changed_attributes_if_nil
      @record = @model.create
      @record.state_event = nil
      
      assert_equal [], @record.changed_columns
    end
  end
  
  class MachineWithoutTransactionsTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :use_transactions => false)
    end
    
    def test_should_not_rollback_transaction_if_false
      @machine.within_transaction(@model.new) do
        @model.create
        false
      end
      
      assert_equal 1, @model.count
    end
    
    def test_should_not_rollback_transaction_if_true
      @machine.within_transaction(@model.new) do
        @model.create
        true
      end
      
      assert_equal 1, @model.count
    end
  end
  
  class MachineWithTransactionsTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :use_transactions => true)
    end
    
    def test_should_rollback_transaction_if_false
      @machine.within_transaction(@model.new) do
        @model.create
        false
      end
      
      assert_equal 0, @model.count
    end
    
    def test_should_not_rollback_transaction_if_true
      @machine.within_transaction(@model.new) do
        @model.create
        true
      end
      
      assert_equal 1, @model.count
    end
  end
  
  class MachineWithCallbacksTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :idling
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
    
    def test_should_pass_transition_to_before_callbacks_with_one_argument
      transition = nil
      @machine.before_transition {|arg| transition = arg}
      
      @transition.perform
      assert_equal @transition, transition
    end
    
    def test_should_pass_transition_to_before_callbacks_with_multiple_arguments
      callback_args = nil
      @machine.before_transition {|*args| callback_args = args}
      
      @transition.perform
      assert_equal [@transition], callback_args
    end
    
    def test_should_run_before_callbacks_within_the_context_of_the_record
      context = nil
      @machine.before_transition {context = self}
      
      @transition.perform
      assert_equal @record, context
    end
    
    def test_should_run_after_callbacks
      called = false
      @machine.after_transition {called = true}
      
      @transition.perform
      assert called
    end
    
    def test_should_pass_transition_to_after_callbacks_with_multiple_arguments
      callback_args = nil
      @machine.after_transition {|*args| callback_args = args}
      
      @transition.perform
      assert_equal [@transition], callback_args
    end
    
    def test_should_run_after_callbacks_with_the_context_of_the_record
      context = nil
      @machine.after_transition {context = self}
      
      @transition.perform
      assert_equal @record, context
    end
    
    def test_should_run_around_callbacks
      before_called = false
      after_called = [false]
      @machine.around_transition {|block| before_called = true; block.call; after_called[0] = true}
      
      @transition.perform
      assert before_called
      assert after_called[0]
    end
    
    def test_should_run_around_callbacks_with_the_context_of_the_record
      context = nil
      @machine.around_transition {|block| context = self; block.call}
      
      @transition.perform
      assert_equal @record, context
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
      callbacks = []
      
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :idling
      @machine.event :ignite
      @machine.before_transition {callbacks << :before_1; false}
      @machine.before_transition {callbacks << :before_2}
      @machine.after_transition {callbacks << :after}
      @machine.around_transition {|block| callbacks << :around_before; block.call; callbacks << :around_after}
      
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @result = @transition.perform
      
      @callbacks = callbacks
    end
    
    def test_should_not_be_successful
      assert !@result
    end
    
    def test_should_not_change_current_state
      assert_equal 'parked', @record.state
    end
    
    def test_should_not_run_action
      assert @record.new?
    end
    
    def test_should_not_run_further_callbacks
      assert_equal [:before_1], @callbacks
    end
  end
  
  class MachineWithFailedActionTest < BaseTestCase
    def setup
      @model = new_model do
        plugin(:validation_class_methods) if respond_to?(:plugin)
        validates_each :state do |object, attribute, value|
          object.errors[attribute] << 'is invalid' unless %w(first_gear).include?(value)
        end
      end
      
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :idling
      @machine.event :ignite
      
      callbacks = []
      @machine.before_transition {callbacks << :before}
      @machine.after_transition {callbacks << :after}
      @machine.after_failure {callbacks << :after_failure}
      @machine.around_transition {|block| callbacks << :around_before; block.call; callbacks << :around_after}
      
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @result = @transition.perform
      
      @callbacks = callbacks
    end
    
    def test_should_not_be_successful
      assert !@result
    end
    
    def test_should_not_change_current_state
      assert_equal 'parked', @record.state
    end
    
    def test_should_not_save_record
      assert @record.new?
    end
    
    def test_should_run_before_callbacks_and_after_callbacks_with_failures
      assert_equal [:before, :around_before, :after_failure], @callbacks
    end
  end
  
  class MachineWithFailedAfterCallbacksTest < BaseTestCase
     def setup
      callbacks = []
      
      @model = new_model
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :idling
      @machine.event :ignite
      @machine.after_transition {callbacks << :after_1; false}
      @machine.after_transition {callbacks << :after_2}
      @machine.around_transition {|block| callbacks << :around_before; block.call; callbacks << :around_after}
      
      @record = @model.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @result = @transition.perform
      
      @callbacks = callbacks
    end
    
    def test_should_be_successful
      assert @result
    end
    
    def test_should_change_current_state
      assert_equal 'idling', @record.state
    end
    
    def test_should_save_record
      assert !@record.new?
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
      @record.state = 'parked'
      
      @machine.invalidate(@record, :state, :invalid_transition, [[:event, 'park']])
      assert_equal ['cannot transition via "park"'], @record.errors.on(:state)
    end
    
    def test_should_auto_prefix_custom_attributes_on_invalidation
      @machine.invalidate(@record, :event, :invalid)
      
      assert_equal ['is invalid'], @record.errors.on(:state_event)
    end
    
    def test_should_clear_errors_on_reset
      @record.state = 'parked'
      @record.errors.add(:state, 'is invalid')
      
      @machine.reset(@record)
      assert_nil @record.errors.on(:id)
    end
    
    def test_should_be_valid_if_state_is_known
      @record.state = 'parked'
      
      assert @record.valid?
    end
    
    def test_should_not_be_valid_if_state_is_unknown
      @record.state = 'invalid'
      
      assert !@record.valid?
      assert_equal ['state is invalid'], @record.errors.full_messages
    end
  end
  
  class MachineWithValidationsAndCustomAttributeTest < BaseTestCase
    def setup
      @model = new_model do
        alias_method :status, :state
        alias_method :status=, :state=
      end
      
      @machine = StateMachine::Machine.new(@model, :status, :attribute => :state)
      @machine.state :parked
      
      @record = @model.new
    end
    
    def test_should_add_validation_errors_to_custom_attribute
      @record.state = 'invalid'
      
      assert !@record.valid?
      assert_equal ['state is invalid'], @record.errors.full_messages
      
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
      assert_equal ['id cannot be blank', 'state is invalid'], @machine.errors_for(@record).split(', ').sort
    end
    
    def test_should_describe_as_halted_with_no_errors
      assert_equal 'Transition halted', @machine.errors_for(@record)
    end
  end
  
  class MachineWithStateDrivenValidationsTest < BaseTestCase
    def setup
      @model = new_model do
        attr_accessor :seatbelt
      end
      
      @machine = StateMachine::Machine.new(@model)
      @machine.state :first_gear do
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
      record = @model.new(:state => 'first_gear', :seatbelt => true)
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
      assert_equal ['state_event is invalid'], @record.errors.full_messages
    end
    
    def test_should_fail_if_event_has_no_transition
      @record.state = 'idling'
      assert !@record.valid?
      assert_equal ['state_event cannot transition when idling'], @record.errors.full_messages
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
    
    def test_should_not_run_around_callbacks_after_yield
      ran_callback = [false]
      @machine.around_transition {|block| block.call; ran_callback[0] = true }
      
      @record.valid?
      assert !ran_callback[0]
    end
    
    def test_should_not_run_around_callbacks_after_yield_with_failures_disabled_if_validation_fails
      @model.class_eval do
        attr_accessor :seatbelt
        validates_presence_of :seatbelt
      end
      
      ran_callback = [false]
      @machine.around_transition {|block| block.call; ran_callback[0] = true }
      
      @record.valid?
      assert !ran_callback[0]
    end
    
    def test_should_not_run_before_transitions_within_transaction
      @machine.before_transition { self.class.create; raise Sequel::Error::Rollback }
      
      begin
        @record.valid?
      rescue Sequel::Error::Rollback
      end
      
      assert_equal 1, @model.count
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
      assert !@record.save
    end
    
    def test_should_raise_exception_when_enabled_if_event_is_invalid
      @record.state_event = 'invalid'
      @model.raise_on_save_failure = true
      if defined?(Sequel::BeforeHookFailed)
        assert_raise(Sequel::BeforeHookFailed) { @record.save }
      else
        assert_raise(Sequel::Error) { @record.save }
      end
    end
    
    def test_should_fail_if_event_has_no_transition
      @record.state = 'idling'
      assert !@record.save
    end
    
    def test_should_raise_exception_when_enabled_if_event_has_no_transition
      @record.state = 'idling'
      @model.raise_on_save_failure = true
      if defined?(Sequel::BeforeHookFailed)
        assert_raise(Sequel::BeforeHookFailed) { @record.save }
      else
        assert_raise(Sequel::Error) { @record.save }
      end
    end
    
    def test_should_be_successful_if_event_has_transition
      assert @record.save
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
      @model.before_create {|record| false}
      
      ran_callback = false
      @machine.after_transition { ran_callback = true }
      
      @record.save
      assert !ran_callback
    end
    
    if defined?(Sequel::MAJOR) && Sequel::MAJOR >= 3 && Sequel::MINOR >= 7
      def test_should_not_run_failure_callbacks_if_fails
        @model.before_create {|record| false}
        
        ran_callback = false
        @machine.after_failure { ran_callback = true }
        
        @record.save
        assert !ran_callback
      end
    else
      def test_should_run_failure_callbacks_if_fails
        @model.before_create {|record| false}
        
        ran_callback = false
        @machine.after_failure { ran_callback = true }
        
        @record.save
        assert ran_callback
      end
    end
    
    def test_should_not_run_before_transitions_within_transaction
      @machine.before_transition { self.class.create; raise Sequel::Error::Rollback }
      
      begin
        @record.save
      rescue Sequel::Error::Rollback
      end
      
      assert_equal 1, @model.count
    end
    
    def test_should_not_run_around_callbacks_with_failures_disabled_if_fails
      @model.before_create {|record| false}
      
      ran_callback = [false]
      @machine.around_transition {|block| block.call; ran_callback[0] = true }
      
      @record.save
      assert !ran_callback[0]
    end
    
    def test_should_run_around_callbacks_after_yield
      ran_callback = [false]
      @machine.around_transition {|block| block.call; ran_callback[0] = true }
      
      @record.save
      assert ran_callback[0]
    end
    
    if defined?(Sequel::MAJOR) && (Sequel::MAJOR >= 3 || Sequel::MAJOR == 2 && Sequel::MINOR == 12)
      def test_should_run_after_transitions_within_transaction
        @machine.after_transition { self.class.create; raise Sequel::Error::Rollback }
        
        @record.save
        
        assert_equal 0, @model.count
      end
      
      def test_should_run_around_transition_within_transaction
        @machine.around_transition {|block| block.call; self.class.create; raise Sequel::Error::Rollback }
        
        @record.save
        
        assert_equal 0, @model.count
      end
    else
      def test_should_not_run_after_transitions_within_transaction
        @machine.after_transition { self.class.create; raise Sequel::Error::Rollback }
        
        begin
          @record.save
        rescue Sequel::Error::Rollback
        end
        
        assert_equal 2, @model.count
      end
      
      def test_should_not_run_around_transition_within_transaction
        @machine.around_transition {|block| block.call; self.class.create; raise Sequel::Error::Rollback }
        
        begin
          @record.save
        rescue Sequel::Error::Rollback
        end
        
        assert_equal 2, @model.count
      end
    end
  end
  
  class MachineWithEventAttributesOnCustomActionTest < BaseTestCase
    def setup
      @superclass = new_model do
        def persist
          save
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
      
      assert_equal [parked], @model.with_state(:parked).all
    end
    
    def test_should_create_plural_with_scope
      assert @model.respond_to?(:with_states)
    end
    
    def test_should_only_include_records_with_states_in_plural_with_scope
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [parked, idling], @model.with_states(:parked, :idling).all
    end
    
    def test_should_allow_lookup_by_string_name
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [parked, idling], @model.with_states('parked', 'idling').all
    end
    
    def test_should_create_singular_without_scope
      assert @model.respond_to?(:without_state)
    end
    
    def test_should_only_include_records_without_state_in_singular_without_scope
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [parked], @model.without_state(:idling).all
    end
    
    def test_should_create_plural_without_scope
      assert @model.respond_to?(:without_states)
    end
    
    def test_should_only_include_records_without_states_in_plural_without_scope
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      first_gear = @model.create :state => 'first_gear'
      
      assert_equal [parked, idling], @model.without_states(:first_gear).all
    end
    
    def test_should_allow_chaining_scopes_and_filters
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [idling], @model.without_state(:parked).with_state(:idling).all
    end
    
    def test_should_run_on_tables_with_double_underscores
      @model = new_model(:foo__bar)
      @machine = StateMachine::Machine.new(@model)
      @machine.state :parked, :first_gear
      @machine.state :idling, :value => lambda {'idling'}
      
      parked = @model.create :state => 'parked'
      idling = @model.create :state => 'idling'
      
      assert_equal [parked], @model.with_state(:parked).all
    end
  end
  
  class MachineWithScopesAndOwnerSubclassTest < BaseTestCase
    def setup
      @model = new_model
      @machine = StateMachine::Machine.new(@model, :state)
      
      @subclass = Class.new(@model)
      @subclass_machine = @subclass.state_machine(:state) {}
      @subclass_machine.state :parked, :idling, :first_gear
    end
    
    def test_should_only_include_records_with_subclass_states_in_with_scope
      parked = @subclass.create :state => 'parked'
      idling = @subclass.create :state => 'idling'
      
      assert_equal [parked, idling], @subclass.with_states(:parked, :idling).all
    end
    
    def test_should_only_include_records_without_subclass_states_in_without_scope
      parked = @subclass.create :state => 'parked'
      idling = @subclass.create :state => 'idling'
      first_gear = @subclass.create :state => 'first_gear'
      
      assert_equal [parked, idling], @subclass.without_states(:first_gear).all
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
  
  class MachineWithScopesAndJoinsTest < BaseTestCase
    def setup
      @company = new_model(:company)
      SequelTest.const_set('Company', @company)
      
      @vehicle = new_model(:vehicle) do
        many_to_one :company, :class => SequelTest::Company
      end
      DB.alter_table :vehicle do
        add_column :company_id, :integer
      end
      @vehicle.class_eval { get_db_schema(true) }
      SequelTest.const_set('Vehicle', @vehicle)
      
      @company_machine = StateMachine::Machine.new(@company, :initial => :active)
      @vehicle_machine = StateMachine::Machine.new(@vehicle, :initial => :parked)
      @vehicle_machine.state :idling
      
      @ford = @company.create
      @mustang = @vehicle.create(:company => @ford)
    end
    
    def test_should_find_records_in_with_scope
      assert_equal [@mustang], @vehicle.with_states(:parked).join(:company, :id => :company_id).filter(:company__state => 'active').select(:vehicle.*).all
    end
    
    def test_should_find_records_in_without_scope
      assert_equal [@mustang], @vehicle.without_states(:idling).join(:company, :id => :company_id).filter(:company__state => 'active').select(:vehicle.*).all
    end
    
    def teardown
      SequelTest.class_eval do
        remove_const('Vehicle')
        remove_const('Company')
      end
    end
  end
end
