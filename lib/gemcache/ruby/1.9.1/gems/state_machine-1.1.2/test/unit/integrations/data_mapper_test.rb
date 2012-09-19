require File.expand_path(File.dirname(__FILE__) + '/../../test_helper')

require 'dm-core'
require 'dm-core/version' unless defined?(::DataMapper::VERSION)
require 'dm-observer'

if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('0.10.3')
  require 'dm-migrations'
end

# Establish database connection
DataMapper.setup(:default, 'sqlite3::memory:')
DataObjects::Sqlite3.logger = DataObjects::Logger.new("#{File.dirname(__FILE__)}/../../data_mapper.log", :info)

module DataMapperTest
  class BaseTestCase < Test::Unit::TestCase
    def default_test
    end
    
    def teardown
      @resources.uniq.each {|resource| DataMapperTest.send(:remove_const, resource)} if @resources
    end
    
    protected
      # Creates a new DataMapper resource (and the associated table)
      def new_resource(create_table = :foo, &block)
        table_name = create_table || :foo
        name = table_name.to_s.capitalize
        
        resource = Class.new
        DataMapperTest.send(:remove_const, name) if DataMapperTest.const_defined?(name)
        DataMapperTest.const_set(name, resource)
        (@resources ||= []) << name
        
        resource.class_eval do
          include DataMapper::Resource
          
          storage_names[:default] = table_name.to_s
          
          property :id, resource.class_eval('Serial')
          property :state, String
        end
        resource.class_eval(&block) if block_given?
        resource.auto_migrate! if create_table
        resource
      end
      
      # Creates a new DataMapper observer
      def new_observer(resource, &block)
        observer = Class.new do
          include DataMapper::Observer
        end
        observer.observe(resource)
        observer.class_eval(&block) if block_given?
        observer
      end
  end
  
  class IntegrationTest < BaseTestCase
    def test_should_have_an_integration_name
      assert_equal :data_mapper, StateMachine::Integrations::DataMapper.integration_name
    end
    
    def test_should_be_available
      assert StateMachine::Integrations::DataMapper.available?
    end
    
    def test_should_match_if_class_includes_data_mapper
      assert StateMachine::Integrations::DataMapper.matches?(new_resource)
    end
    
    def test_should_not_match_if_class_does_not_include_data_mapper
      assert !StateMachine::Integrations::DataMapper.matches?(Class.new)
    end
    
    def test_should_have_defaults
      assert_equal e = {:action => :save, :use_transactions => false}, StateMachine::Integrations::DataMapper.defaults
    end
    
    def test_should_not_have_a_locale_path
      assert_nil StateMachine::Integrations::DataMapper.locale_path
    end
  end
  
  class MachineWithoutDatabaseTest < BaseTestCase
    def setup
      @resource = new_resource(false) do
        # Simulate the database not being available entirely
        def self.repository
          raise DataObjects::SyntaxError
        end
      end
    end
    
    def test_should_allow_machine_creation
      assert_nothing_raised { StateMachine::Machine.new(@resource) }
    end
  end
  
  class MachineUnmigratedTest < BaseTestCase
    def setup
      @resource = new_resource(false)
    end
    
    def test_should_allow_machine_creation
      assert_nothing_raised { StateMachine::Machine.new(@resource) }
    end
  end
  
  class MachineWithoutPropertyTest < BaseTestCase
    def setup
      @resource = new_resource
      StateMachine::Machine.new(@resource, :status)
    end
    
    def test_should_define_field_with_string_type
      property = @resource.properties.detect {|property| property.name == :status}
      assert_not_nil property
      
      if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('1.0.0')
        assert_instance_of DataMapper::Property::String, property
      else
        assert_equal String, property.type
      end
    end
  end
  
  class MachineWithPropertyTest < BaseTestCase
    def setup
      @resource = new_resource do
        property :status, Integer
      end
      StateMachine::Machine.new(@resource, :status)
    end
    
    def test_should_not_redefine_field
      property = @resource.properties.detect {|property| property.name == :status}
      assert_not_nil property
      
      if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('1.0.0')
        assert_instance_of DataMapper::Property::Integer, property
      else
        assert_equal Integer, property.type
      end
    end
  end
  
  class MachineByDefaultTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource)
    end
    
    def test_should_use_save_as_action
      assert_equal :save, @machine.action
    end
    
    def test_should_not_use_transactions
      assert_equal false, @machine.use_transactions
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
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource)
      @machine.state :first_gear
    end
    
    def test_should_humanize_name
      assert_equal 'first gear', @machine.state(:first_gear).human_name
    end
  end
  
  class MachineWithStaticInitialStateTest < BaseTestCase
    def setup
      @resource = new_resource do
        attr_accessor :value
      end
      @machine = StateMachine::Machine.new(@resource, :initial => :parked)
    end
    
    def test_should_set_initial_state_on_created_object
      record = @resource.new
      assert_equal 'parked', record.state
    end
    
    def test_should_set_initial_state_with_nil_attributes
      @resource.class_eval do
        def attributes=(attributes)
          super(attributes || {})
        end
      end
      
      record = @resource.new(nil)
      assert_equal 'parked', record.state
    end
    
    def test_should_still_set_attributes
      record = @resource.new(:value => 1)
      assert_equal 1, record.value
    end
    
    def test_should_not_allow_initialize_blocks
      block_args = nil
      record = @resource.new do |*args|
        block_args = args
      end
      
      assert_nil block_args
    end
    
    def test_should_set_initial_state_before_setting_attributes
      @resource.class_eval do
        attr_accessor :state_during_setter
        
        define_method(:value=) do |value|
          self.state_during_setter = state
        end
      end
      
      record = @resource.new(:value => 1)
      assert_equal 'parked', record.state_during_setter
    end
    
    def test_should_not_set_initial_state_after_already_initialized
      record = @resource.new(:value => 1)
      assert_equal 'parked', record.state
      
      record.state = 'idling'
      record.attributes = {}
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database
      @machine.state :idling
      
      record = @resource.get(@resource.create(:state => 'idling').id)
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database_with_nil_state
      @machine.state nil
      
      record = @resource.get(@resource.create(:state => nil).id)
      assert_nil record.state
    end
  end
  
  class MachineWithDynamicInitialStateTest < BaseTestCase
    def setup
      @resource = new_resource do
        attr_accessor :value
      end
      @machine = StateMachine::Machine.new(@resource, :initial => lambda {|object| :parked})
      @machine.state :parked
    end
    
    def test_should_set_initial_state_on_created_object
      record = @resource.new
      assert_equal 'parked', record.state
    end
    
    def test_should_still_set_attributes
      record = @resource.new(:value => 1)
      assert_equal 1, record.value
    end
    
    def test_should_not_allow_initialize_blocks
      block_args = nil
      record = @resource.new do |*args|
        block_args = args
      end
      
      assert_nil block_args
    end
    
    def test_should_set_initial_state_after_setting_attributes
      @resource.class_eval do
        attr_accessor :state_during_setter
        
        define_method(:value=) do |value|
          self.state_during_setter = state || 'nil'
        end
      end
      
      record = @resource.new(:value => 1)
      assert_equal 'nil', record.state_during_setter
    end
    
    def test_should_not_set_initial_state_after_already_initialized
      record = @resource.new(:value => 1)
      assert_equal 'parked', record.state
      
      record.state = 'idling'
      record.attributes = {}
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database
      @machine.state :idling
      
      record = @resource.get(@resource.create(:state => 'idling').id)
      assert_equal 'idling', record.state
    end
    
    def test_should_use_stored_values_when_loading_from_database_with_nil_state
      @machine.state nil
      
      record = @resource.get(@resource.create(:state => nil).id)
      assert_nil record.state
    end
  end
  
  class MachineWithEventsTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource)
      @machine.event :shift_up
    end
    
    def test_should_humanize_name
      assert_equal 'shift up', @machine.event(:shift_up).human_name
    end
  end
  
  class MachineWithColumnDefaultTest < BaseTestCase
    def setup
      @resource = new_resource do
        property :status, String, :default => 'idling'
      end
      @machine = StateMachine::Machine.new(@resource, :status, :initial => :parked)
      @record = @resource.new
    end
    
    def test_should_use_machine_default
      assert_equal 'parked', @record.status
    end
  end
  
  class MachineWithConflictingPredicateTest < BaseTestCase
    def setup
      @resource = new_resource do
        def state?(*args)
          true
        end
      end
      
      @machine = StateMachine::Machine.new(@resource)
      @record = @resource.new
    end
    
    def test_should_not_define_attribute_predicate
      assert @record.state?
    end
  end
  
  class MachineWithConflictingStateNameTest < BaseTestCase
    def setup
      require 'stringio'
      @original_stderr, $stderr = $stderr, StringIO.new
      
      @resource = new_resource
    end
    
    def test_should_output_warning_with_same_machine_name
      @machine = StateMachine::Machine.new(@resource)
      @machine.state :state
      
      assert_match /^Instance method "state\?" is already defined in DataMapperTest::Foo :state instance helpers, use generic helper instead.*\n$/, $stderr.string
    end
    
    def test_should_not_output_warning_with_same_machine_name
      @machine = StateMachine::Machine.new(@resource, :public_state, :attribute => :state)
      @machine.state :state
      
      assert_equal '', $stderr.string
    end
    
    def teardown
      $stderr = @original_stderr
      super
    end
  end
  
  class MachineWithColumnStateAttributeTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource, :initial => :parked)
      @machine.other_states(:idling)
      
      @record = @resource.new
    end
    
    def test_should_not_override_the_column_reader
      @record.attribute_set(:state, 'parked')
      assert_equal 'parked', @record.state
    end
    
    def test_should_not_override_the_column_writer
      @record.state = 'parked'
      assert_equal 'parked', @record.attribute_get(:state)
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
      @resource = new_resource do
        def initialize
          # Skip attribute initialization
          @initialized_state_machines = true
          super
        end
      end
      
      @machine = StateMachine::Machine.new(@resource, :status, :initial => 'parked')
      @record = @resource.new
    end
    
    def test_should_define_a_new_property_for_the_attribute
      assert_not_nil @resource.properties[:status]
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
      @resource = new_resource do
        attr_accessor :status
      end
      
      @machine = StateMachine::Machine.new(@resource, :status, :initial => :parked)
      @machine.other_states(:idling)
      @record = @resource.new
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
  
  class MachineWithInitializedStateTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource, :initial => :parked)
      @machine.state :idling
    end
    
    def test_should_allow_nil_initial_state_when_static
      @machine.state nil
      
      record = @resource.new(:state => nil)
      assert_nil record.state
    end
    
    def test_should_allow_nil_initial_state_when_dynamic
      @machine.state nil
      
      @machine.initial_state = lambda {:parked}
      record = @resource.new(:state => nil)
      assert_nil record.state
    end
    
    def test_should_allow_different_initial_state_when_static
      record = @resource.new(:state => 'idling')
      assert_equal 'idling', record.state
    end
    
    def test_should_allow_different_initial_state_when_dynamic
      @machine.initial_state = lambda {:parked}
      record = @resource.new(:state => 'idling')
      assert_equal 'idling', record.state
    end
    
    if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('0.9.8')
      def test_should_raise_exception_if_protected
        resource = new_resource do
          protected :state=
        end
        
        machine = StateMachine::Machine.new(resource, :initial => :parked)
        machine.state :idling
        
        assert_raise(ArgumentError) { resource.new(:state => 'idling') }
      end
    end
  end
  
  class MachineMultipleTest < BaseTestCase
    def setup
      @resource = new_resource do
        property :status, String
      end
      @state_machine = StateMachine::Machine.new(@resource, :initial => :parked)
      @status_machine = StateMachine::Machine.new(@resource, :status, :initial => :idling)
    end
    
    def test_should_should_initialize_each_state
      record = @resource.new
      assert_equal 'parked', record.state
      assert_equal 'idling', record.status
    end
  end
  
  class MachineWithLoopbackTest < BaseTestCase
    def setup
      @resource = new_resource do
        property :updated_at, DateTime
        
        # Simulate dm-timestamps
        before :update do
          return unless dirty?
          self.updated_at = DateTime.now
        end
      end
      
      @machine = StateMachine::Machine.new(@resource, :initial => :parked)
      @machine.event :park
      
      @record = @resource.create(:updated_at => Time.now - 1)
      @transition = StateMachine::Transition.new(@record, @machine, :park, :parked, :parked)
      
      @timestamp = @record.updated_at
      @transition.perform
    end
    
    def test_should_not_update_record
      assert_equal @timestamp, @record.updated_at
    end
  end
  
  class MachineWithDirtyAttributesTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource, :initial => :parked)
      @machine.event :ignite
      @machine.state :idling
      
      @record = @resource.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @transition.perform(false)
    end
    
    def test_should_include_state_in_changed_attributes
      assert_equal e = {@resource.properties[:state] => 'idling'}, @record.dirty_attributes
    end
    
    def test_should_track_attribute_change
      if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('0.10.0')
        assert_equal e = {@resource.properties[:state] => 'parked'}, @record.original_attributes
      else
        assert_equal e = {:state => 'parked'},  @record.original_values
      end
    end
    
    def test_should_not_reset_changes_on_multiple_transitions
      transition = StateMachine::Transition.new(@record, @machine, :ignite, :idling, :idling)
      transition.perform(false)
      
      if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('0.10.0')
        assert_equal e = {@resource.properties[:state] => 'parked'}, @record.original_attributes
      else
        assert_equal e = {:state => 'parked'},  @record.original_values
      end
    end
    
    def test_should_not_have_changes_when_loaded_from_database
      record = @resource.get(@record.id)
      assert record.dirty_attributes.empty?
    end
  end
  
  class MachineWithDirtyAttributesDuringLoopbackTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource, :initial => :parked)
      @machine.event :park
      
      @record = @resource.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :park, :parked, :parked)
      @transition.perform(false)
    end
    
    def test_should_not_include_state_in_changed_attributes
      assert_equal e = {}, @record.dirty_attributes
    end
  end
  
  class MachineWithDirtyAttributesAndCustomAttributeTest < BaseTestCase
    def setup
      @resource = new_resource do
        property :status, String, :default => 'idling'
      end
      @machine = StateMachine::Machine.new(@resource, :status, :initial => :parked)
      @machine.event :ignite
      @machine.state :idling
      
      @record = @resource.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      @transition.perform(false)
    end
    
    def test_should_include_state_in_changed_attributes
      assert_equal e = {@resource.properties[:status] => 'idling'}, @record.dirty_attributes
    end
    
    def test_should_track_attribute_change
      if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('0.10.0')
        assert_equal e = {@resource.properties[:status] => 'parked'}, @record.original_attributes
      else
        assert_equal e = {:status => 'parked'},  @record.original_values
      end
    end
    
    def test_should_not_reset_changes_on_multiple_transitions
      transition = StateMachine::Transition.new(@record, @machine, :ignite, :idling, :idling)
      transition.perform(false)
      
      if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('0.10.0')
        assert_equal e = {@resource.properties[:status] => 'parked'}, @record.original_attributes
      else
        assert_equal e = {:status => 'parked'},  @record.original_values
      end
    end
  end
  
  class MachineWithDirtyAttributeAndCustomAttributesDuringLoopbackTest < BaseTestCase
    def setup
      @resource = new_resource do
        property :status, String, :default => 'idling'
      end
      @machine = StateMachine::Machine.new(@resource, :status, :initial => :parked)
      @machine.event :park
      
      @record = @resource.create
      
      @transition = StateMachine::Transition.new(@record, @machine, :park, :parked, :parked)
      @transition.perform(false)
    end
    
    def test_should_not_include_state_in_changed_attributes
      assert_equal e = {}, @record.dirty_attributes
    end
  end
  
  class MachineWithDirtyAttributeAndStateEventsTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource, :initial => :parked)
      @machine.event :ignite
      
      @record = @resource.create
      @record.state_event = 'ignite'
    end
    
    def test_should_not_include_state_in_changed_attributes
      assert_equal e = {}, @record.dirty_attributes
    end
    
    def test_should_not_track_attribute_change
      if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('0.10.0')
        assert_equal e = {}, @record.original_attributes
      else
        assert_equal e = {},  @record.original_values
      end
    end
  end
  
  class MachineWithoutTransactionsTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource, :use_transactions => false)
    end
    
    def test_should_not_rollback_transaction_if_false
      @machine.within_transaction(@resource.new) do
        @resource.create
        false
      end
      
      assert_equal 1, @resource.all.size
    end
    
    def test_should_not_rollback_transaction_if_true
      @machine.within_transaction(@resource.new) do
        @resource.create
        true
      end
      
      assert_equal 1, @resource.all.size
    end
  end
  
  begin
    if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('0.10.3')
      require 'dm-transactions'
    end
    
    class MachineWithTransactionsTest < BaseTestCase
      def setup
        @resource = new_resource
        @machine = StateMachine::Machine.new(@resource, :use_transactions => true)
      end
      
      def test_should_rollback_transaction_if_false
        @machine.within_transaction(@resource.new) do
          @resource.create
          false
        end
        
        assert_equal 0, @resource.all.size
      end
      
      def test_should_not_rollback_transaction_if_true
        @machine.within_transaction(@resource.new) do
          @resource.create
          true
        end
        
        assert_equal 1, @resource.all.size
      end
    end
  rescue LoadError
    $stderr.puts "Skipping DataMapper Transaction tests."
  end
  
  class MachineWithCallbacksTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource)
      @machine.state :parked, :idling
      @machine.event :ignite
      
      @record = @resource.new(:state => 'parked')
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
      
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource)
      @machine.state :parked, :idling
      @machine.event :ignite
      @machine.before_transition {callbacks << :before_1; throw :halt}
      @machine.before_transition {callbacks << :before_2}
      @machine.after_transition {callbacks << :after}
      @machine.around_transition {|block| callbacks << :around_before; block.call; callbacks << :around_after}
      
      @record = @resource.new(:state => 'parked')
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
      assert @record.respond_to?(:new?) ? @record.new? : @record.new_record?
    end
    
    def test_should_not_run_further_callbacks
      assert_equal [:before_1], @callbacks
    end
  end
  
  class MachineWithFailedActionTest < BaseTestCase
    def setup
      @resource = new_resource do
        before(:create) { throw :halt }
      end
      
      @machine = StateMachine::Machine.new(@resource)
      @machine.state :parked, :idling
      @machine.event :ignite
      
      callbacks = []
      @machine.before_transition {callbacks << :before}
      @machine.after_transition {callbacks << :after}
      @machine.after_failure {callbacks << :after_failure}
      @machine.around_transition {|block| callbacks << :around_before; block.call; callbacks << :around_after}
      
      @record = @resource.new(:state => 'parked')
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
      assert @record.respond_to?(:new?) ? @record.new? : @record.new_record?
    end
    
    def test_should_run_before_callbacks_and_after_callbacks_with_failures
      assert_equal [:before, :around_before, :after_failure], @callbacks
    end
  end
  
  class MachineWithFailedAfterCallbacksTest < BaseTestCase
     def setup
      callbacks = []
      
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource)
      @machine.state :parked, :idling
      @machine.event :ignite
      @machine.after_transition {callbacks << :after_1; throw :halt}
      @machine.after_transition {callbacks << :after_2}
      @machine.around_transition {|block| callbacks << :around_before; block.call; callbacks << :around_after}
      
      @record = @resource.new(:state => 'parked')
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
      assert !(@record.respond_to?(:new?) ? @record.new? : @record.new_record?)
    end
    
    def test_should_not_run_further_after_callbacks
      assert_equal [:around_before, :around_after, :after_1], @callbacks
    end
  end
  
  begin
    require 'dm-validations'
    
    class MachineWithValidationsTest < BaseTestCase
      def setup
        @resource = new_resource
        @machine = StateMachine::Machine.new(@resource)
        @machine.state :parked
        
        @record = @resource.new
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
        assert_equal ['is invalid'], @record.errors.on(:state)
      end
    end
    
    class MachineWithValidationsAndCustomAttributeTest < BaseTestCase
      def setup
        @resource = new_resource
        @machine = StateMachine::Machine.new(@resource, :status, :attribute => :state)
        @machine.state :parked
        
        @record = @resource.new
      end
      
      def test_should_add_validation_errors_to_custom_attribute
        @record.state = 'invalid'
        
        assert !@record.valid?
        assert_equal ['is invalid'], @record.errors.on(:state)
        
        @record.state = 'parked'
        assert @record.valid?
      end
    end
    
    class MachineErrorsTest < BaseTestCase
      def setup
        @resource = new_resource
        @machine = StateMachine::Machine.new(@resource)
        @record = @resource.new
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
        @resource = resource = new_resource do
          attr_accessor :seatbelt
        end
        
        @machine = StateMachine::Machine.new(@resource)
        @machine.state :first_gear, :second_gear do
          if resource.respond_to?(:validates_presence_of)
            validates_presence_of :seatbelt
          else
            validates_present :seatbelt
          end
        end
        @machine.other_states :parked
      end
      
      def test_should_be_valid_if_validation_fails_outside_state_scope
        record = @resource.new(:state => 'parked', :seatbelt => nil)
        assert record.valid?
      end
      
      def test_should_be_invalid_if_validation_fails_within_state_scope
        record = @resource.new(:state => 'first_gear', :seatbelt => nil)
        assert !record.valid?
      end
      
      def test_should_be_valid_if_validation_succeeds_within_state_scope
        record = @resource.new(:state => 'second_gear', :seatbelt => true)
        assert record.valid?
      end
    end
    
    # See README caveats
    if Gem::Version.new(::DataMapper::VERSION) > Gem::Version.new('0.9.6')
      class MachineWithEventAttributesOnValidationTest < BaseTestCase
        def setup
          @resource = new_resource
          @machine = StateMachine::Machine.new(@resource)
          @machine.event :ignite do
            transition :parked => :idling
          end
          
          @record = @resource.new
          @record.state = 'parked'
          @record.state_event = 'ignite'
        end
        
        def test_should_fail_if_event_is_invalid
          @record.state_event = 'invalid'
          assert !@record.valid?
          assert_equal ['is invalid'], @record.errors.full_messages
        end
        
        def test_should_fail_if_event_has_no_transition
          @record.state = 'idling'
          assert !@record.valid?
          assert_equal ['cannot transition when idling'], @record.errors.full_messages
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
          @resource.class_eval do
            attr_accessor :seatbelt
            if respond_to?(:validates_presence_of)
              validates_presence_of :seatbelt
            else
              validates_present :seatbelt
            end
          end
          
          ran_callback = false
          @machine.after_transition { ran_callback = true }
          
          @record.valid?
          assert !ran_callback
        end
        
        def test_should_run_failure_callbacks_if_validation_fails
          @resource.class_eval do
            attr_accessor :seatbelt
            if respond_to?(:validates_presence_of)
              validates_presence_of :seatbelt
            else
              validates_present :seatbelt
            end
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
          @resource.class_eval do
            attr_accessor :seatbelt
            if respond_to?(:validates_presence_of)
              validates_presence_of :seatbelt
            else
              validates_present :seatbelt
            end
          end
          
          ran_callback = [false]
          @machine.around_transition {|block| block.call; ran_callback[0] = true }
          
          @record.valid?
          assert !ran_callback[0]
        end
        
        def test_should_not_run_before_transitions_within_transaction
          @machine.before_transition { self.class.create; throw :halt }
          
          assert !@record.valid?
          assert_equal 1, @resource.all.size
        end
      end
      
      class MachineWithEventAttributesOnSaveTest < BaseTestCase
        def setup
          @resource = new_resource
          @machine = StateMachine::Machine.new(@resource)
          @machine.event :ignite do
            transition :parked => :idling
          end
          
          @record = @resource.new
          @record.state = 'parked'
          @record.state_event = 'ignite'
        end
        
        def test_should_fail_if_event_is_invalid
          @record.state_event = 'invalid'
          assert !@record.save
        end
        
        def test_should_fail_if_event_has_no_transition
          @record.state = 'idling'
          assert !@record.save
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
          @resource.before(:create) { throw :halt }
          
          ran_callback = false
          @machine.after_transition { ran_callback = true }
          
          @record.save
          assert !ran_callback
        end
        
        def test_should_run_failure_callbacks_if_fails
          @resource.before(:create) { throw :halt }
          
          ran_callback = false
          @machine.after_failure { ran_callback = true }
          
          @record.save
          assert ran_callback
        end
        
        def test_should_not_run_around_callbacks_with_failures_disabled_if_fails
          @resource.before(:create) { throw :halt }
          
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
        
        def test_should_not_run_before_transitions_within_transaction
          @machine.before_transition { self.class.create; throw :halt }
          
          assert_equal false, @record.save
          assert_equal 1, @resource.all.size
        end
        
        def test_should_not_run_after_transitions_within_transaction
          @machine.before_transition { self.class.create; throw :halt }
          
          assert_equal false, @record.save
          assert_equal 1, @resource.all.size
        end
        
        def test_should_not_run_around_transition_within_transaction
          @machine.around_transition { self.class.create; throw :halt }
          
          assert_equal false, @record.save
          assert_equal 1, @resource.all.size
        end
      end
    end
    
    if Gem::Version.new(::DataMapper::VERSION) >= Gem::Version.new('0.10.0')
      class MachineWithEventAttributesOnSaveBangTest < BaseTestCase
        def setup
          @resource = new_resource
          @machine = StateMachine::Machine.new(@resource)
          @machine.event :ignite do
            transition :parked => :idling
          end
          
          @record = @resource.new
          @record.state = 'parked'
          @record.state_event = 'ignite'
        end
        
        def test_should_fail_if_event_is_invalid
          @record.state_event = 'invalid'
          assert !@record.save!
        end
        
        def test_should_fail_if_event_has_no_transition
          @record.state = 'idling'
          assert !@record.save!
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
        
        def test_should_run_after_callbacks
          ran_callback = false
          @machine.after_transition { ran_callback = true }
          
          @record.save!
          assert ran_callback
        end
        
        def test_should_run_around_callbacks_after_yield
          ran_callback = [false]
          @machine.around_transition {|block| block.call; ran_callback[0] = true }
          
          @record.save!
          assert ran_callback[0]
        end
      end
    end
    
    if Gem::Version.new(::DataMapper::VERSION) > Gem::Version.new('0.9.6')
      class MachineWithEventAttributesOnCustomActionTest < BaseTestCase
        def setup
          @superclass = new_resource do
            def persist
              save
            end
          end
          @resource = Class.new(@superclass)
          @machine = StateMachine::Machine.new(@resource, :action => :persist)
          @machine.event :ignite do
            transition :parked => :idling
          end
          
          @record = @resource.new
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
    end
  rescue LoadError
    $stderr.puts "Skipping DataMapper Validation tests."
  end
  
  class MachineWithObserversTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource)
      @machine.state :parked, :idling
      @machine.event :ignite
      @record = @resource.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
    end
    
    def test_should_provide_matcher_helpers
      matchers = []
      
      new_observer(@resource) do
        matchers = [all, any, same]
      end
      
      assert_equal [StateMachine::AllMatcher.instance, StateMachine::AllMatcher.instance, StateMachine::LoopbackMatcher.instance], matchers
    end
    
    def test_should_call_before_transition_callback_if_requirements_match
      called = false
      
      observer = new_observer(@resource) do
        before_transition :from => :parked do
          called = true
        end
      end
      
      @transition.perform
      assert called
    end
    
    def test_should_not_call_before_transition_callback_if_requirements_do_not_match
      called = false
      
      observer = new_observer(@resource) do
        before_transition :from => :idling do
          called = true
        end
      end
      
      @transition.perform
      assert !called
    end
    
    def test_should_pass_transition_to_before_callbacks
      callback_args = nil
      
      observer = new_observer(@resource) do
        before_transition do |*args|
          callback_args = args
        end
      end
      
      @transition.perform
      assert_equal [@transition], callback_args
    end
    
    def test_should_call_after_transition_callback_if_requirements_match
      called = false
      
      observer = new_observer(@resource) do
        after_transition :from => :parked do
          called = true
        end
      end
      
      @transition.perform
      assert called
    end
    
    def test_should_not_call_after_transition_callback_if_requirements_do_not_match
      called = false
      
      observer = new_observer(@resource) do
        after_transition :from => :idling do
          called = true
        end
      end
      
      @transition.perform
      assert !called
    end
    
    def test_should_pass_transition_to_after_callbacks
      callback_args = nil
      
      observer = new_observer(@resource) do
        after_transition do |*args|
          callback_args = args
        end
      end
      
      @transition.perform
      assert_equal [@transition], callback_args
    end
    
    def test_should_call_around_transition_callback_if_requirements_match
      called = false
      
      observer = new_observer(@resource) do
        around_transition :from => :parked do |block|
          called = true
          block.call
        end
      end
      
      @transition.perform
      assert called
    end
    
    def test_should_not_call_after_transition_callback_if_requirements_do_not_match
      called = false
      
      observer = new_observer(@resource) do
        around_transition :from => :idling do |block|
          called = true
          block.call
        end
      end
      
      @transition.perform
      assert !called
    end
    
    def test_should_pass_transition_to_around_callbacks
      callback_args = nil
      
      observer = new_observer(@resource) do
        around_transition do |*args|
          block = args.pop
          callback_args = args
          block.call
        end
      end
      
      @transition.perform
      assert_equal [@transition], callback_args
    end
    
    def test_should_call_failure_callback_if_requirements_match
      @resource.before(:create) { throw :halt } 
      
      called = false
      
      observer = new_observer(@resource) do
        after_transition_failure :on => :ignite do
          called = true
        end
      end
      
      @transition.perform
      assert called
    end
    
    def test_should_not_call_failure_callback_if_requirements_do_not_match
      @resource.before(:create) { throw :halt } 
      
      called = false
      
      observer = new_observer(@resource) do
        after_transition_failure :on => :park do
          called = true
        end
      end
      
      @transition.perform
      assert !called
    end
    
    def test_should_pass_transition_to_failure_callbacks
      @resource.before(:create) { throw :halt } 
      
      callback_args = nil
      
      observer = new_observer(@resource) do
        after_transition_failure do |*args|
          callback_args = args
        end
      end
      
      @transition.perform
      assert_equal [@transition], callback_args
    end
    
    def test_should_raise_exception_if_targeting_invalid_machine
      assert_raise(RUBY_VERSION < '1.9' ? IndexError : KeyError) do
        new_observer(@resource) do
          before_transition :invalid, :from => :parked do
          end
        end
      end
    end
    
    def test_should_allow_targeting_specific_machine
      @second_machine = StateMachine::Machine.new(@resource, :status, :namespace => 'alarm')
      @resource.auto_migrate!
      
      called_state = false
      called_status = false
      
      observer = new_observer(@resource) do
        before_transition :state, :from => :parked do
          called_state = true
        end
        
        before_transition :status, :from => :parked do
          called_status = true
        end
      end
      
      @transition.perform
      
      assert called_state
      assert !called_status
    end
    
    def test_should_allow_targeting_multiple_specific_machines
      @second_machine = StateMachine::Machine.new(@resource, :status, :namespace => 'alarm')
      @second_machine.state :parked, :idling
      @second_machine.event :ignite
      @resource.auto_migrate!
      
      called_attribute = nil
      
      attributes = []
      observer = new_observer(@resource) do
        before_transition :state, :status, :from => :parked do |transition|
          called_attribute = transition.attribute
        end
      end
      
      @transition.perform
      assert_equal :state, called_attribute
      
      StateMachine::Transition.new(@record, @second_machine, :ignite, :parked, :idling).perform
      assert_equal :status, called_attribute
    end
  end
  
  class MachineWithMixedCallbacksTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource)
      @machine.state :parked, :idling
      @machine.event :ignite
      @record = @resource.new(:state => 'parked')
      @transition = StateMachine::Transition.new(@record, @machine, :ignite, :parked, :idling)
      
      @notifications = notifications = []
      
      # Create callbacks
      @machine.before_transition {notifications << :callback_before_transition}
      @machine.after_transition {notifications << :callback_after_transition}
      @machine.around_transition do |block|
        notifications << :callback_around_before_transition
        block.call
        notifications << :callback_around_after_transition
      end
      
      observer = new_observer(@resource) do
        before_transition do
          notifications << :observer_before_transition
        end
        
        after_transition do
          notifications << :observer_after_transition
        end
        
        around_transition do |block|
          notifications << :observer_around_before_transition
          block.call
          notifications << :observer_around_after_transition
        end
      end
      
      @transition.perform
    end
    
    def test_should_invoke_callbacks_in_specific_order
      expected = [
        :callback_before_transition,
        :callback_around_before_transition,
        :observer_before_transition,
        :observer_around_before_transition,
        :observer_around_after_transition,
        :callback_around_after_transition,
        :callback_after_transition,
        :observer_after_transition
      ]
      
      assert_equal expected, @notifications
    end
  end
  
  class MachineWithScopesTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource)
      @machine.state :parked, :first_gear
      @machine.state :idling, :value => lambda {'idling'}
    end
    
    def test_should_create_singular_with_scope
      assert @resource.respond_to?(:with_state)
    end
    
    def test_should_only_include_records_with_state_in_singular_with_scope
      parked = @resource.create :state => 'parked'
      idling = @resource.create :state => 'idling'
      
      assert_equal [parked], @resource.with_state(:parked)
    end
    
    def test_should_create_plural_with_scope
      assert @resource.respond_to?(:with_states)
    end
    
    def test_should_only_include_records_with_states_in_plural_with_scope
      parked = @resource.create :state => 'parked'
      idling = @resource.create :state => 'idling'
      
      assert_equal [parked, idling], @resource.with_states(:parked, :idling)
    end
    
    def test_should_allow_lookup_by_string_name
      parked = @resource.create :state => 'parked'
      idling = @resource.create :state => 'idling'
      
      assert_equal [parked, idling], @resource.with_states('parked', 'idling')
    end
    
    def test_should_create_singular_without_scope
      assert @resource.respond_to?(:without_state)
    end
    
    def test_should_only_include_records_without_state_in_singular_without_scope
      parked = @resource.create :state => 'parked'
      idling = @resource.create :state => 'idling'
      
      assert_equal [parked], @resource.without_state(:idling)
    end
    
    def test_should_create_plural_without_scope
      assert @resource.respond_to?(:without_states)
    end
    
    def test_should_only_include_records_without_states_in_plural_without_scope
      parked = @resource.create :state => 'parked'
      idling = @resource.create :state => 'idling'
      first_gear = @resource.create :state => 'first_gear'
      
      assert_equal [parked, idling], @resource.without_states(:first_gear)
    end
    
    def test_should_allow_chaining_scopes
      parked = @resource.create :state => 'parked'
      idling = @resource.create :state => 'idling'
      
      assert_equal [idling], @resource.without_state(:parked).with_state(:idling)
    end
  end
  
  class MachineWithScopesAndOwnerSubclassTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource, :state)
      
      @subclass = Class.new(@resource)
      DataMapperTest.const_set('Bar', @subclass)
      @resources << 'Bar'
      @subclass.auto_migrate!
      @subclass_machine = @subclass.state_machine(:state) {}
      @subclass_machine.state :parked, :idling, :first_gear
    end
    
    def test_should_only_include_records_with_subclass_states_in_with_scope
      parked = @subclass.create :state => 'parked'
      idling = @subclass.create :state => 'idling'
      
      assert_equal [parked, idling], @subclass.with_states(:parked, :idling)
    end
    
    def test_should_only_include_records_without_subclass_states_in_without_scope
      parked = @subclass.create :state => 'parked'
      idling = @subclass.create :state => 'idling'
      first_gear = @subclass.create :state => 'first_gear'
      
      assert_equal [parked, idling], @subclass.without_states(:first_gear)
    end
  end
  
  class MachineWithComplexPluralizationScopesTest < BaseTestCase
    def setup
      @resource = new_resource
      @machine = StateMachine::Machine.new(@resource, :status)
    end
    
    def test_should_create_singular_with_scope
      assert @resource.respond_to?(:with_status)
    end
    
    def test_should_create_plural_with_scope
      assert @resource.respond_to?(:with_statuses)
    end
  end
  
  class MachineWithScopesAndJoinsTest < BaseTestCase
    def setup
      @company = new_resource(:company)
      
      @vehicle = new_resource(:vehicle) do
        property :company_id, Integer
        
        belongs_to :company
      end
      
      @company_machine = StateMachine::Machine.new(@company, :initial => :active)
      @vehicle_machine = StateMachine::Machine.new(@vehicle, :initial => :parked)
      @vehicle_machine.state :idling
      
      @ford = @company.create
      @mustang = @vehicle.create(:company => @ford)
    end
    
    def test_should_find_records_in_with_scope
      assert_equal [@mustang], @vehicle.with_states(:parked).all(Vehicle.company.state => 'active')
    end
    
    def test_should_find_records_in_without_scope
      assert_equal [@mustang], @vehicle.without_states(:idling).all(Vehicle.company.state => 'active')
    end
  end
end
