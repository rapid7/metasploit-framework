require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class MachineByDefaultTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @object = @klass.new
  end
  
  def test_should_have_an_owner_class
    assert_equal @klass, @machine.owner_class
  end
  
  def test_should_have_a_name
    assert_equal :state, @machine.name
  end
  
  def test_should_have_an_attribute
    assert_equal :state, @machine.attribute
  end
  
  def test_should_prefix_custom_attributes_with_attribute
    assert_equal :state_event, @machine.attribute(:event)
  end
  
  def test_should_have_an_initial_state
    assert_not_nil @machine.initial_state(@object)
  end
  
  def test_should_have_a_nil_initial_state
    assert_nil @machine.initial_state(@object).value
  end
  
  def test_should_not_have_any_events
    assert !@machine.events.any?
  end
  
  def test_should_not_have_any_before_callbacks
    assert @machine.callbacks[:before].empty?
  end
  
  def test_should_not_have_any_after_callbacks
    assert @machine.callbacks[:after].empty?
  end
  
  def test_should_not_have_any_failure_callbacks
    assert @machine.callbacks[:failure].empty?
  end
  
  def test_should_not_have_an_action
    assert_nil @machine.action
  end
  
  def test_should_use_tranactions
    assert_equal true, @machine.use_transactions
  end
  
  def test_should_not_have_a_namespace
    assert_nil @machine.namespace
  end
  
  def test_should_have_a_nil_state
    assert_equal [nil], @machine.states.keys
  end
  
  def test_should_set_initial_on_nil_state
    assert @machine.state(nil).initial
  end
  
  def test_should_generate_default_messages
    assert_equal 'is invalid', @machine.generate_message(:invalid)
    assert_equal 'cannot transition when parked', @machine.generate_message(:invalid_event, [[:state, :parked]])
    assert_equal 'cannot transition via "park"', @machine.generate_message(:invalid_transition, [[:event, :park]])
  end
  
  def test_should_not_be_extended_by_the_base_integration
    assert !(class << @machine; ancestors; end).include?(StateMachine::Integrations::Base)
  end
  
  def test_should_not_be_extended_by_the_active_model_integration
    assert !(class << @machine; ancestors; end).include?(StateMachine::Integrations::ActiveModel)
  end
  
  def test_should_not_be_extended_by_the_active_record_integration
    assert !(class << @machine; ancestors; end).include?(StateMachine::Integrations::ActiveRecord)
  end
  
  def test_should_not_be_extended_by_the_datamapper_integration
    assert !(class << @machine; ancestors; end).include?(StateMachine::Integrations::DataMapper)
  end
  
  def test_should_not_be_extended_by_the_mongo_mapper_integration
    assert !(class << @machine; ancestors; end).include?(StateMachine::Integrations::MongoMapper)
  end
  
  def test_should_not_be_extended_by_the_sequel_integration
    assert !(class << @machine; ancestors; end).include?(StateMachine::Integrations::Sequel)
  end
  
  def test_should_define_a_reader_attribute_for_the_attribute
    assert @object.respond_to?(:state)
  end
  
  def test_should_define_a_writer_attribute_for_the_attribute
    assert @object.respond_to?(:state=)
  end
  
  def test_should_define_a_predicate_for_the_attribute
    assert @object.respond_to?(:state?)
  end
  
  def test_should_define_a_name_reader_for_the_attribute
    assert @object.respond_to?(:state_name)
  end
  
  def test_should_define_an_event_reader_for_the_attribute
    assert @object.respond_to?(:state_events)
  end
  
  def test_should_define_a_transition_reader_for_the_attribute
    assert @object.respond_to?(:state_transitions)
  end
  
  def test_should_define_a_path_reader_for_the_attribute
    assert @object.respond_to?(:state_paths)
  end
  
  def test_should_define_an_event_runner_for_the_attribute
    assert @object.respond_to?(:fire_state_event)
  end
  
  def test_should_not_define_an_event_attribute_reader
    assert !@object.respond_to?(:state_event)
  end
  
  def test_should_not_define_an_event_attribute_writer
    assert !@object.respond_to?(:state_event=)
  end
  
  def test_should_not_define_an_event_transition_attribute_reader
    assert !@object.respond_to?(:state_event_transition)
  end
  
  def test_should_not_define_an_event_transition_attribute_writer
    assert !@object.respond_to?(:state_event_transition=)
  end
  
  def test_should_define_a_human_attribute_name_reader_for_the_attribute
    assert @klass.respond_to?(:human_state_name)
  end
  
  def test_should_define_a_human_event_name_reader_for_the_attribute
    assert @klass.respond_to?(:human_state_event_name)
  end
  
  def test_should_not_define_singular_with_scope
    assert !@klass.respond_to?(:with_state)
  end
  
  def test_should_not_define_singular_without_scope
    assert !@klass.respond_to?(:without_state)
  end
  
  def test_should_not_define_plural_with_scope
    assert !@klass.respond_to?(:with_states)
  end
  
  def test_should_not_define_plural_without_scope
    assert !@klass.respond_to?(:without_states)
  end
  
  def test_should_extend_owner_class_with_class_methods
    assert (class << @klass; ancestors; end).include?(StateMachine::ClassMethods)
  end
  
  def test_should_include_instance_methods_in_owner_class
    assert @klass.included_modules.include?(StateMachine::InstanceMethods)
  end
  
  def test_should_define_state_machines_reader
    expected = {:state => @machine}
    assert_equal expected, @klass.state_machines
  end
end

class MachineWithCustomNameTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :status)
    @object = @klass.new
  end
  
  def test_should_use_custom_name
    assert_equal :status, @machine.name
  end
  
  def test_should_use_custom_name_for_attribute
    assert_equal :status, @machine.attribute
  end
  
  def test_should_prefix_custom_attributes_with_custom_name
    assert_equal :status_event, @machine.attribute(:event)
  end
  
  def test_should_define_a_reader_attribute_for_the_attribute
    assert @object.respond_to?(:status)
  end
  
  def test_should_define_a_writer_attribute_for_the_attribute
    assert @object.respond_to?(:status=)
  end
  
  def test_should_define_a_predicate_for_the_attribute
    assert @object.respond_to?(:status?)
  end
  
  def test_should_define_a_name_reader_for_the_attribute
    assert @object.respond_to?(:status_name)
  end
  
  def test_should_define_an_event_reader_for_the_attribute
    assert @object.respond_to?(:status_events)
  end
  
  def test_should_define_a_transition_reader_for_the_attribute
    assert @object.respond_to?(:status_transitions)
  end
  
  def test_should_define_an_event_runner_for_the_attribute
    assert @object.respond_to?(:fire_status_event)
  end
  
  def test_should_define_a_human_attribute_name_reader_for_the_attribute
    assert @klass.respond_to?(:human_status_name)
  end
  
  def test_should_define_a_human_event_name_reader_for_the_attribute
    assert @klass.respond_to?(:human_status_event_name)
  end
end

class MachineWithoutInitializationTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def initialize(attributes = {})
        attributes.each {|attr, value| send("#{attr}=", value)}
        super()
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked, :initialize => false)
  end
  
  def test_should_not_have_an_initial_state
    object = @klass.new
    assert_nil object.state
  end
  
  def test_should_still_allow_manual_initialization
    @klass.class_eval do
      def initialize(attributes = {})
        attributes.each {|attr, value| send("#{attr}=", value)}
        super()
        initialize_state_machines
      end
    end
    
    object = @klass.new
    assert_equal 'parked', object.state
  end
end

class MachineWithStaticInitialStateTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
  end
  
  def test_should_not_have_dynamic_initial_state
    assert !@machine.dynamic_initial_state?
  end
  
  def test_should_have_an_initial_state
    object = @klass.new
    assert_equal 'parked', @machine.initial_state(object).value
  end
  
  def test_should_write_to_attribute_when_initializing_state
    object = @klass.allocate
    @machine.initialize_state(object)
    assert_equal 'parked', object.state
  end
  
  def test_should_set_initial_on_state_object
    assert @machine.state(:parked).initial
  end
  
  def test_should_set_initial_state_on_created_object
    assert_equal 'parked', @klass.new.state
  end
  
  def test_should_still_set_initial_state_even_if_not_empty
    @klass.class_eval do
      def initialize(attributes = {})
        self.state = 'idling'
        super()
      end
    end
    object = @klass.new
    assert_equal 'parked', object.state
  end
  
  def test_should_set_initial_state_prior_to_initialization
    base = Class.new do
      attr_accessor :state_on_init
      
      def initialize
        self.state_on_init = state
      end
    end
    klass = Class.new(base)
    machine = StateMachine::Machine.new(klass, :initial => :parked)
    
    assert_equal 'parked', klass.new.state_on_init
  end
  
  def test_should_be_included_in_known_states
    assert_equal [:parked], @machine.states.keys
  end
end

class MachineWithDynamicInitialStateTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_accessor :initial_state
    end
    @machine = StateMachine::Machine.new(@klass, :initial => lambda {|object| object.initial_state || :default})
    @machine.state :parked, :idling, :default
    @object = @klass.new
  end
  
  def test_should_have_dynamic_initial_state
    assert @machine.dynamic_initial_state?
  end
  
  def test_should_use_the_record_for_determining_the_initial_state
    @object.initial_state = :parked
    assert_equal :parked, @machine.initial_state(@object).name
    
    @object.initial_state = :idling
    assert_equal :idling, @machine.initial_state(@object).name
  end
  
  def test_should_write_to_attribute_when_initializing_state
    object = @klass.allocate
    object.initial_state = :parked
    @machine.initialize_state(object)
    assert_equal 'parked', object.state
  end
  
  def test_should_set_initial_state_on_created_object
    assert_equal 'default', @object.state
  end
  
  def test_should_not_set_initial_state_even_if_not_empty
    @klass.class_eval do
      def initialize(attributes = {})
        self.state = 'parked'
        super()
      end
    end
    object = @klass.new
    assert_equal 'parked', object.state
  end
  
  def test_should_set_initial_state_after_initialization
    base = Class.new do
      attr_accessor :state_on_init
      
      def initialize
        self.state_on_init = state
      end
    end
    klass = Class.new(base)
    machine = StateMachine::Machine.new(klass, :initial => lambda {|object| :parked})
    machine.state :parked
    
    assert_nil klass.new.state_on_init
  end
  
  def test_should_not_be_included_in_known_states
    assert_equal [:parked, :idling, :default], @machine.states.map {|state| state.name}
  end
end

class MachineStateInitializationTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :state, :initial => :parked, :initialize => false)
    
    @object = @klass.new
    @object.state = nil
  end
  
  def test_should_set_states_if_nil
    @machine.initialize_state(@object)
    
    assert_equal 'parked', @object.state
  end
  
  def test_should_set_states_if_empty
    @object.state = ''
    @machine.initialize_state(@object)
    
    assert_equal 'parked', @object.state
  end
  
  def test_should_not_set_states_if_not_empty
    @object.state = 'idling'
    @machine.initialize_state(@object)
    
    assert_equal 'idling', @object.state
  end
  
  def test_should_set_states_if_not_empty_and_forced
    @object.state = 'idling'
    @machine.initialize_state(@object, :force => true)
    
    assert_equal 'parked', @object.state
  end
  
  def test_should_not_set_state_if_nil_and_nil_is_valid_state
    @machine.state :initial, :value => nil
    @machine.initialize_state(@object)
    
    assert_nil @object.state
  end
  
  def test_should_write_to_hash_if_specified
    @machine.initialize_state(@object, :to => hash = {})
    assert_equal expected = {'state' => 'parked'}, hash
  end
  
  def test_should_not_write_to_object_if_writing_to_hash
    @machine.initialize_state(@object, :to => {})
    assert_nil @object.state
  end
end

class MachineWithCustomActionTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new, :action => :save)
  end
  
  def test_should_use_the_custom_action
    assert_equal :save, @machine.action
  end
end

class MachineWithNilActionTest < Test::Unit::TestCase
  def setup
    integration = Module.new do
      include StateMachine::Integrations::Base
      
      @defaults = {:action => :save}
    end
    StateMachine::Integrations.const_set('Custom', integration)
    @machine = StateMachine::Machine.new(Class.new, :action => nil, :integration => :custom)
  end
  
  def test_should_have_a_nil_action
    assert_nil @machine.action
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class MachineWithoutIntegrationTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @object = @klass.new
  end
  
  def test_transaction_should_yield
    @yielded = false
    @machine.within_transaction(@object) do
      @yielded = true
    end
    
    assert @yielded
  end
  
  def test_invalidation_should_do_nothing
    assert_nil @machine.invalidate(@object, :state, :invalid_transition, [[:event, 'park']])
  end
  
  def test_reset_should_do_nothing
    assert_nil @machine.reset(@object)
  end
  
  def test_errors_for_should_be_empty
    assert_equal '', @machine.errors_for(@object)
  end
end

class MachineWithCustomIntegrationTest < Test::Unit::TestCase
  def setup
    integration = Module.new do
      include StateMachine::Integrations::Base
      
      def self.matching_ancestors
        ['MachineWithCustomIntegrationTest::Vehicle']
      end
    end
    
    StateMachine::Integrations.const_set('Custom', integration)
    
    superclass = Class.new
    self.class.const_set('Vehicle', superclass)
    
    @klass = Class.new(superclass)
  end
  
  def test_should_be_extended_by_the_integration_if_explicit
    machine = StateMachine::Machine.new(@klass, :integration => :custom)
    assert (class << machine; ancestors; end).include?(StateMachine::Integrations::Custom)
  end
  
  def test_should_not_be_extended_by_the_integration_if_implicit_but_not_available
    StateMachine::Integrations::Custom.class_eval do
      def self.matching_ancestors
        []
      end
    end
    
    machine = StateMachine::Machine.new(@klass)
    assert !(class << machine; ancestors; end).include?(StateMachine::Integrations::Custom)
  end

  def test_should_not_be_extended_by_the_integration_if_implicit_but_not_matched
    StateMachine::Integrations::Custom.class_eval do
      def self.matching_ancestors
        []
      end
    end
    
    machine = StateMachine::Machine.new(@klass)
    assert !(class << machine; ancestors; end).include?(StateMachine::Integrations::Custom)
  end

  def test_should_be_extended_by_the_integration_if_implicit_and_available_and_matches
    machine = StateMachine::Machine.new(@klass)
    assert (class << machine; ancestors; end).include?(StateMachine::Integrations::Custom)
  end

  def test_should_not_be_extended_by_the_integration_if_nil
    machine = StateMachine::Machine.new(@klass, :integration => nil)
    assert !(class << machine; ancestors; end).include?(StateMachine::Integrations::Custom)
  end
  
  def test_should_not_be_extended_by_the_integration_if_false
    machine = StateMachine::Machine.new(@klass, :integration => false)
    assert !(class << machine; ancestors; end).include?(StateMachine::Integrations::Custom)
  end
  
  def teardown
    self.class.send(:remove_const, 'Vehicle')
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class MachineWithIntegrationTest < Test::Unit::TestCase
  def setup
    StateMachine::Integrations.const_set('Custom', Module.new do  
      include StateMachine::Integrations::Base
      
      @defaults = {:action => :save, :use_transactions => false}
          
      attr_reader :initialized, :with_scopes, :without_scopes, :ran_transaction
      
      def after_initialize
        @initialized = true
      end
      
      def create_with_scope(name)
        (@with_scopes ||= []) << name
        lambda {}
      end
      
      def create_without_scope(name)
        (@without_scopes ||= []) << name
        lambda {}
      end
      
      def transaction(object)
        @ran_transaction = true
        yield
      end
    end)
    
    @machine = StateMachine::Machine.new(Class.new, :integration => :custom)
  end
  
  def test_should_call_after_initialize_hook
    assert @machine.initialized
  end
  
  def test_should_use_the_default_action
    assert_equal :save, @machine.action
  end
  
  def test_should_use_the_custom_action_if_specified
    machine = StateMachine::Machine.new(Class.new, :integration => :custom, :action => :save!)
    assert_equal :save!, machine.action
  end
  
  def test_should_use_the_default_use_transactions
    assert_equal false, @machine.use_transactions
  end
  
  def test_should_use_the_custom_use_transactions_if_specified
    machine = StateMachine::Machine.new(Class.new, :integration => :custom, :use_transactions => true)
    assert_equal true, machine.use_transactions
  end
  
  def test_should_define_a_singular_and_plural_with_scope
    assert_equal %w(with_state with_states), @machine.with_scopes
  end
  
  def test_should_define_a_singular_and_plural_without_scope
    assert_equal %w(without_state without_states), @machine.without_scopes
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class MachineWithActionUndefinedTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @object = @klass.new
  end
  
  def test_should_define_an_event_attribute_reader
    assert @object.respond_to?(:state_event)
  end
  
  def test_should_define_an_event_attribute_writer
    assert @object.respond_to?(:state_event=)
  end
  
  def test_should_define_an_event_transition_attribute_reader
    assert @object.respond_to?(:state_event_transition)
  end
  
  def test_should_define_an_event_transition_attribute_writer
    assert @object.respond_to?(:state_event_transition=)
  end
  
  def test_should_not_define_action
    assert !@object.respond_to?(:save)
  end
  
  def test_should_not_mark_action_hook_as_defined
    assert !@machine.action_hook?
  end
end

class MachineWithActionDefinedInClassTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def save
      end
    end
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @object = @klass.new
  end
  
  def test_should_define_an_event_attribute_reader
    assert @object.respond_to?(:state_event)
  end
  
  def test_should_define_an_event_attribute_writer
    assert @object.respond_to?(:state_event=)
  end
  
  def test_should_define_an_event_transition_attribute_reader
    assert @object.respond_to?(:state_event_transition)
  end
  
  def test_should_define_an_event_transition_attribute_writer
    assert @object.respond_to?(:state_event_transition=)
  end
  
  def test_should_not_define_action
    assert !@klass.ancestors.any? {|ancestor| ancestor != @klass && ancestor.method_defined?(:save)}
  end
  
  def test_should_not_mark_action_hook_as_defined
    assert !@machine.action_hook?
  end
end

class MachineWithActionDefinedInIncludedModuleTest < Test::Unit::TestCase
  def setup
    @mod = mod = Module.new do
      def save
      end
    end
    
    @klass = Class.new do
      include mod
    end
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @object = @klass.new
  end
  
  def test_should_define_an_event_attribute_reader
    assert @object.respond_to?(:state_event)
  end
  
  def test_should_define_an_event_attribute_writer
    assert @object.respond_to?(:state_event=)
  end
  
  def test_should_define_an_event_transition_attribute_reader
    assert @object.respond_to?(:state_event_transition)
  end
  
  def test_should_define_an_event_transition_attribute_writer
    assert @object.respond_to?(:state_event_transition=)
  end
  
  def test_should_define_action
    assert @klass.ancestors.any? {|ancestor| ![@klass, @mod].include?(ancestor) && ancestor.method_defined?(:save)}
  end
  
  def test_should_keep_action_public
    assert @klass.public_method_defined?(:save)
  end
  
  def test_should_mark_action_hook_as_defined
    assert @machine.action_hook?
  end
end

class MachineWithActionDefinedInSuperclassTest < Test::Unit::TestCase
  def setup
    @superclass = Class.new do
      def save
      end
    end
    @klass = Class.new(@superclass)
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @object = @klass.new
  end
  
  def test_should_define_an_event_attribute_reader
    assert @object.respond_to?(:state_event)
  end
  
  def test_should_define_an_event_attribute_writer
    assert @object.respond_to?(:state_event=)
  end
  
  def test_should_define_an_event_transition_attribute_reader
    assert @object.respond_to?(:state_event_transition)
  end
  
  def test_should_define_an_event_transition_attribute_writer
    assert @object.respond_to?(:state_event_transition=)
  end
  
  def test_should_define_action
    assert @klass.ancestors.any? {|ancestor| ![@klass, @superclass].include?(ancestor) && ancestor.method_defined?(:save)}
  end
  
  def test_should_keep_action_public
    assert @klass.public_method_defined?(:save)
  end
  
  def test_should_mark_action_hook_as_defined
    assert @machine.action_hook?
  end
end

class MachineWithPrivateActionTest < Test::Unit::TestCase
  def setup
    @superclass = Class.new do
      private
      def save
      end
    end
    @klass = Class.new(@superclass)
    
    @machine = StateMachine::Machine.new(@klass, :action => :save)
    @object = @klass.new
  end
  
  def test_should_define_an_event_attribute_reader
    assert @object.respond_to?(:state_event)
  end
  
  def test_should_define_an_event_attribute_writer
    assert @object.respond_to?(:state_event=)
  end
  
  def test_should_define_an_event_transition_attribute_reader
    assert @object.respond_to?(:state_event_transition)
  end
  
  def test_should_define_an_event_transition_attribute_writer
    assert @object.respond_to?(:state_event_transition=)
  end
  
  def test_should_define_action
    assert @klass.ancestors.any? {|ancestor| ![@klass, @superclass].include?(ancestor) && ancestor.private_method_defined?(:save)}
  end
  
  def test_should_keep_action_private
    assert @klass.private_method_defined?(:save)
  end
  
  def test_should_mark_action_hook_as_defined
    assert @machine.action_hook?
  end
end

class MachineWithActionAlreadyOverriddenTest < Test::Unit::TestCase
  def setup
    @superclass = Class.new do
      def save
      end
    end
    @klass = Class.new(@superclass)
    
    StateMachine::Machine.new(@klass, :action => :save)
    @machine = StateMachine::Machine.new(@klass, :status, :action => :save)
    @object = @klass.new
  end
  
  def test_should_not_redefine_action
    assert_equal 1, @klass.ancestors.select {|ancestor| ![@klass, @superclass].include?(ancestor) && ancestor.method_defined?(:save)}.length
  end
  
  def test_should_mark_action_hook_as_defined
    assert @machine.action_hook?
  end
end

class MachineWithCustomPluralTest < Test::Unit::TestCase
  def setup
    @integration = Module.new do
      include StateMachine::Integrations::Base
      
      class << self; attr_accessor :with_scopes, :without_scopes; end
      @with_scopes = []
      @without_scopes = []
      
      def create_with_scope(name)
        StateMachine::Integrations::Custom.with_scopes << name
        lambda {}
      end
      
      def create_without_scope(name)
        StateMachine::Integrations::Custom.without_scopes << name
        lambda {}
      end
    end
    
    StateMachine::Integrations.const_set('Custom', @integration)
    @machine = StateMachine::Machine.new(Class.new, :integration => :custom, :plural => 'staties')
  end
  
  def test_should_define_a_singular_and_plural_with_scope
    assert_equal %w(with_state with_staties), @integration.with_scopes
  end
  
  def test_should_define_a_singular_and_plural_without_scope
    assert_equal %w(without_state without_staties), @integration.without_scopes
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class MachineWithCustomInvalidationTest < Test::Unit::TestCase
  def setup
    @integration = Module.new do
      include StateMachine::Integrations::Base
      
      def invalidate(object, attribute, message, values = [])
        object.error = generate_message(message, values)
      end
    end
    StateMachine::Integrations.const_set('Custom', @integration)
    
    @klass = Class.new do
      attr_accessor :error
    end
    
    @machine = StateMachine::Machine.new(@klass, :integration => :custom, :messages => {:invalid_transition => 'cannot %s'})
    @machine.state :parked
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_generate_custom_message
    assert_equal 'cannot park', @machine.generate_message(:invalid_transition, [[:event, :park]])
  end
  
  def test_use_custom_message
    @machine.invalidate(@object, :state, :invalid_transition, [[:event, 'park']])
    assert_equal 'cannot park', @object.error
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class MachineTest < Test::Unit::TestCase
  def test_should_raise_exception_if_invalid_option_specified
    assert_raise(ArgumentError) {StateMachine::Machine.new(Class.new, :invalid => true)}
  end
  
  def test_should_not_raise_exception_if_custom_messages_specified
    assert_nothing_raised {StateMachine::Machine.new(Class.new, :messages => {:invalid_transition => 'custom'})}
  end
  
  def test_should_evaluate_a_block_during_initialization
    called = true
    StateMachine::Machine.new(Class.new) do
      called = respond_to?(:event)
    end
    
    assert called
  end
  
  def test_should_provide_matcher_helpers_during_initialization
    matchers = []
    
    StateMachine::Machine.new(Class.new) do
      matchers = [all, any, same]
    end
    
    assert_equal [StateMachine::AllMatcher.instance, StateMachine::AllMatcher.instance, StateMachine::LoopbackMatcher.instance], matchers
  end
end

class MachineAfterBeingCopiedTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new, :state, :initial => :parked)
    @machine.event(:ignite) {}
    @machine.before_transition(lambda {})
    @machine.after_transition(lambda {})
    @machine.around_transition(lambda {})
    @machine.after_failure(lambda {})
    
    @copied_machine = @machine.clone
  end
  
  def test_should_not_have_the_same_collection_of_states
    assert_not_same @copied_machine.states, @machine.states
  end
  
  def test_should_copy_each_state
    assert_not_same @copied_machine.states[:parked], @machine.states[:parked]
  end
  
  def test_should_update_machine_for_each_state
    assert_equal @copied_machine, @copied_machine.states[:parked].machine
  end
  
  def test_should_not_update_machine_for_original_state
    assert_equal @machine, @machine.states[:parked].machine
  end
  
  def test_should_not_have_the_same_collection_of_events
    assert_not_same @copied_machine.events, @machine.events
  end
  
  def test_should_copy_each_event
    assert_not_same @copied_machine.events[:ignite], @machine.events[:ignite]
  end
  
  def test_should_update_machine_for_each_event
    assert_equal @copied_machine, @copied_machine.events[:ignite].machine
  end
  
  def test_should_not_update_machine_for_original_event
    assert_equal @machine, @machine.events[:ignite].machine
  end
  
  def test_should_not_have_the_same_callbacks
    assert_not_same @copied_machine.callbacks, @machine.callbacks
  end
  
  def test_should_not_have_the_same_before_callbacks
    assert_not_same @copied_machine.callbacks[:before], @machine.callbacks[:before]
  end
  
  def test_should_not_have_the_same_after_callbacks
    assert_not_same @copied_machine.callbacks[:after], @machine.callbacks[:after]
  end
  
  def test_should_not_have_the_same_failure_callbacks
    assert_not_same @copied_machine.callbacks[:failure], @machine.callbacks[:failure]
  end
end

class MachineAfterChangingOwnerClassTest < Test::Unit::TestCase
  def setup
    @original_class = Class.new
    @machine = StateMachine::Machine.new(@original_class)
    
    @new_class = Class.new(@original_class)
    @new_machine = @machine.clone
    @new_machine.owner_class = @new_class
    
    @object = @new_class.new
  end
  
  def test_should_update_owner_class
    assert_equal @new_class, @new_machine.owner_class
  end
  
  def test_should_not_change_original_owner_class
    assert_equal @original_class, @machine.owner_class
  end
  
  def test_should_change_the_associated_machine_in_the_new_class
    assert_equal @new_machine, @new_class.state_machines[:state]
  end
  
  def test_should_not_change_the_associated_machine_in_the_original_class
    assert_equal @machine, @original_class.state_machines[:state]
  end
end

class MachineAfterChangingInitialState < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @machine.initial_state = :idling
    
    @object = @klass.new
  end
  
  def test_should_change_the_initial_state
    assert_equal :idling, @machine.initial_state(@object).name
  end
  
  def test_should_include_in_known_states
    assert_equal [:parked, :idling], @machine.states.map {|state| state.name}
  end
  
  def test_should_reset_original_initial_state
    assert !@machine.state(:parked).initial
  end
  
  def test_should_set_new_state_to_initial
    assert @machine.state(:idling).initial
  end
end

class MachineWithHelpersTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @object = @klass.new
  end
  
  def test_should_throw_exception_with_invalid_scope
    assert_raise(RUBY_VERSION < '1.9' ? IndexError : KeyError) { @machine.define_helper(:invalid, :park) {} }
  end
end

class MachineWithInstanceHelpersTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @object = @klass.new
  end
  
  def test_should_not_redefine_existing_public_methods
    @klass.class_eval do
      def park
        true
      end
    end
    
    @machine.define_helper(:instance, :park) {}
    assert_equal true, @object.park
  end
  
  def test_should_not_redefine_existing_protected_methods
    @klass.class_eval do
      protected
        def park
          true
        end
    end
    
    @machine.define_helper(:instance, :park) {}
    assert_equal true, @object.send(:park)
  end
  
  def test_should_not_redefine_existing_private_methods
    @klass.class_eval do
      private
        def park
          true
        end
    end
    
    @machine.define_helper(:instance, :park) {}
    assert_equal true, @object.send(:park)
  end
  
  def test_should_warn_if_defined_in_superclass
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    superclass = Class.new do
      def park
      end
    end
    klass = Class.new(superclass)
    machine = StateMachine::Machine.new(klass)
    
    machine.define_helper(:instance, :park) {}
    assert_equal "Instance method \"park\" is already defined in #{superclass.to_s}, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n", $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_warn_if_defined_in_multiple_superclasses
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    superclass1 = Class.new do
      def park
      end
    end
    superclass2 = Class.new(superclass1) do
      def park
      end
    end
    klass = Class.new(superclass2)
    machine = StateMachine::Machine.new(klass)
    
    machine.define_helper(:instance, :park) {}
    assert_equal "Instance method \"park\" is already defined in #{superclass1.to_s}, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n", $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_warn_if_defined_in_module_prior_to_helper_module
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    mod = Module.new do
      def park
      end
    end
    klass = Class.new do
      include mod
    end
    machine = StateMachine::Machine.new(klass)
    
    machine.define_helper(:instance, :park) {}
    assert_equal "Instance method \"park\" is already defined in #{mod.to_s}, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n", $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_not_warn_if_defined_in_module_after_helper_module
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    klass = Class.new
    machine = StateMachine::Machine.new(klass)
    
    mod = Module.new do
      def park
      end
    end
    klass.class_eval do
      include mod
    end
    
    machine.define_helper(:instance, :park) {}
    assert_equal '', $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_define_if_ignoring_method_conflicts_and_defined_in_superclass
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    StateMachine::Machine.ignore_method_conflicts = true
    
    superclass = Class.new do
      def park
      end
    end
    klass = Class.new(superclass)
    machine = StateMachine::Machine.new(klass)
    
    machine.define_helper(:instance, :park) {true}
    assert_equal '', $stderr.string
    assert_equal true, klass.new.park
  ensure
    StateMachine::Machine.ignore_method_conflicts = false
    $stderr = @original_stderr
  end
  
  def test_should_define_nonexistent_methods
    @machine.define_helper(:instance, :park) {false}
    assert_equal false, @object.park
  end
  
  def test_should_warn_if_defined_multiple_times
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    @machine.define_helper(:instance, :park) {}
    @machine.define_helper(:instance, :park) {}
    
    assert_equal "Instance method \"park\" is already defined in #{@klass} :state instance helpers, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n", $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_pass_context_as_arguments
    helper_args = nil
    @machine.define_helper(:instance, :park) {|*args| helper_args = args}
    @object.park
    assert_equal 2, helper_args.length
    assert_equal [@machine, @object], helper_args
  end
  
  def test_should_pass_method_arguments_through
    helper_args = nil
    @machine.define_helper(:instance, :park) {|*args| helper_args = args}
    @object.park(1, 2, 3)
    assert_equal 5, helper_args.length
    assert_equal [@machine, @object, 1, 2, 3], helper_args
  end
  
  def test_should_allow_string_evaluation
    @machine.define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
      def park
        false
      end
    end_eval
    assert_equal false, @object.park
  end
end

class MachineWithClassHelpersTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
  end
  
  def test_should_not_redefine_existing_public_methods
    class << @klass
      def states
        []
      end
    end
    
    @machine.define_helper(:class, :states) {}
    assert_equal [], @klass.states
  end
  
  def test_should_not_redefine_existing_protected_methods
    class << @klass
      protected
        def states
          []
        end
    end
    
    @machine.define_helper(:class, :states) {}
    assert_equal [], @klass.send(:states)
  end
  
  def test_should_not_redefine_existing_private_methods
    class << @klass
      private
        def states
          []
        end
    end
    
    @machine.define_helper(:class, :states) {}
    assert_equal [], @klass.send(:states)
  end
  
  def test_should_warn_if_defined_in_superclass
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    superclass = Class.new do
      def self.park
      end
    end
    klass = Class.new(superclass)
    machine = StateMachine::Machine.new(klass)
    
    machine.define_helper(:class, :park) {}
    assert_equal "Class method \"park\" is already defined in #{superclass.to_s}, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n", $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_warn_if_defined_in_multiple_superclasses
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    superclass1 = Class.new do
      def self.park
      end
    end
    superclass2 = Class.new(superclass1) do
      def self.park
      end
    end
    klass = Class.new(superclass2)
    machine = StateMachine::Machine.new(klass)
    
    machine.define_helper(:class, :park) {}
    assert_equal "Class method \"park\" is already defined in #{superclass1.to_s}, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n", $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_warn_if_defined_in_module_prior_to_helper_module
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    mod = Module.new do
      def park
      end
    end
    klass = Class.new do
      extend mod
    end
    machine = StateMachine::Machine.new(klass)
    
    machine.define_helper(:class, :park) {}
    assert_equal "Class method \"park\" is already defined in #{mod.to_s}, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n", $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_not_warn_if_defined_in_module_after_helper_module
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    klass = Class.new
    machine = StateMachine::Machine.new(klass)
    
    mod = Module.new do
      def park
      end
    end
    klass.class_eval do
      extend mod
    end
    
    machine.define_helper(:class, :park) {}
    assert_equal '', $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_define_if_ignoring_method_conflicts_and_defined_in_superclass
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    StateMachine::Machine.ignore_method_conflicts = true
    
    superclass = Class.new do
      def self.park
      end
    end
    klass = Class.new(superclass)
    machine = StateMachine::Machine.new(klass)
    
    machine.define_helper(:class, :park) {true}
    assert_equal '', $stderr.string
    assert_equal true, klass.park
  ensure
    StateMachine::Machine.ignore_method_conflicts = false
    $stderr = @original_stderr
  end
  
  def test_should_define_nonexistent_methods
    @machine.define_helper(:class, :states) {[]}
    assert_equal [], @klass.states
  end
  
  def test_should_warn_if_defined_multiple_times
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    @machine.define_helper(:class, :states) {}
    @machine.define_helper(:class, :states) {}
    
    assert_equal "Class method \"states\" is already defined in #{@klass} :state class helpers, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n", $stderr.string
  ensure
    $stderr = @original_stderr
  end
  
  def test_should_pass_context_as_arguments
    helper_args = nil
    @machine.define_helper(:class, :states) {|*args| helper_args = args}
    @klass.states
    assert_equal 2, helper_args.length
    assert_equal [@machine, @klass], helper_args
  end
  
  def test_should_pass_method_arguments_through
    helper_args = nil
    @machine.define_helper(:class, :states) {|*args| helper_args = args}
    @klass.states(1, 2, 3)
    assert_equal 5, helper_args.length
    assert_equal [@machine, @klass, 1, 2, 3], helper_args
  end
  
  def test_should_allow_string_evaluation
    @machine.define_helper :class, <<-end_eval, __FILE__, __LINE__ + 1
      def states
        []
      end
    end_eval
    assert_equal [], @klass.states
  end
end

class MachineWithConflictingHelpersBeforeDefinitionTest < Test::Unit::TestCase
  def setup
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    @superclass = Class.new do
      def self.with_state
        :with_state
      end
      
      def self.with_states
        :with_states
      end
      
      def self.without_state
        :without_state
      end
      
      def self.without_states
        :without_states
      end
      
      def self.human_state_name
        :human_state_name
      end
      
      def self.human_state_event_name
        :human_state_event_name
      end
      
      attr_accessor :status
      
      def state
        'parked'
      end
      
      def state=(value)
        self.status = value
      end
      
      def state?
        true
      end
      
      def state_name
        :parked
      end
      
      def human_state_name
        'parked'
      end
      
      def state_events
        [:ignite]
      end
      
      def state_transitions
        [{:parked => :idling}]
      end
      
      def state_paths
        [[{:parked => :idling}]]
      end
      
      def fire_state_event
        true
      end
    end
    @klass = Class.new(@superclass)
    
    StateMachine::Integrations.const_set('Custom', Module.new do
      include StateMachine::Integrations::Base
      
      def create_with_scope(name)
        lambda {|klass, values| []}
      end
      
      def create_without_scope(name)
        lambda {|klass, values| []}
      end
    end)
    
    @machine = StateMachine::Machine.new(@klass, :integration => :custom)
    @machine.state :parked, :idling
    @machine.event :ignite
    @object = @klass.new
  end
  
  def test_should_not_redefine_singular_with_scope
    assert_equal :with_state, @klass.with_state
  end
  
  def test_should_not_redefine_plural_with_scope
    assert_equal :with_states, @klass.with_states
  end
  
  def test_should_not_redefine_singular_without_scope
    assert_equal :without_state, @klass.without_state
  end
  
  def test_should_not_redefine_plural_without_scope
    assert_equal :without_states, @klass.without_states
  end
  
  def test_should_not_redefine_human_attribute_name_reader
    assert_equal :human_state_name, @klass.human_state_name
  end
  
  def test_should_not_redefine_human_event_name_reader
    assert_equal :human_state_event_name, @klass.human_state_event_name
  end
  
  def test_should_not_redefine_attribute_writer
    assert_equal 'parked', @object.state
  end
  
  def test_should_not_redefine_attribute_writer
    @object.state = 'parked'
    assert_equal 'parked', @object.status
  end
  
  def test_should_not_define_attribute_predicate
    assert @object.state?
  end
  
  def test_should_not_redefine_attribute_name_reader
    assert_equal :parked, @object.state_name
  end
  
  def test_should_not_redefine_attribute_human_name_reader
    assert_equal 'parked', @object.human_state_name
  end
  
  def test_should_not_redefine_attribute_events_reader
    assert_equal [:ignite], @object.state_events
  end
  
  def test_should_not_redefine_attribute_transitions_reader
    assert_equal [{:parked => :idling}], @object.state_transitions
  end
  
  def test_should_not_redefine_attribute_paths_reader
    assert_equal [[{:parked => :idling}]], @object.state_paths
  end
  
  def test_should_not_redefine_event_runner
    assert_equal true, @object.fire_state_event
  end
  
  def test_should_output_warning
    expected = [
      'Instance method "state_events"',
      'Instance method "state_transitions"',
      'Instance method "fire_state_event"',
      'Instance method "state_paths"',
      'Class method "human_state_name"',
      'Class method "human_state_event_name"',
      'Instance method "state_name"',
      'Instance method "human_state_name"',
      'Class method "with_state"',
      'Class method "without_state"',
      'Class method "with_states"',
      'Class method "without_states"'
    ].map {|method| "#{method} is already defined in #{@superclass.to_s}, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.\n"}.join
    
    assert_equal expected, $stderr.string
  end
  
  def teardown
    $stderr = @original_stderr
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class MachineWithConflictingHelpersAfterDefinitionTest < Test::Unit::TestCase
  def setup
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    @klass = Class.new do
      def self.with_state
        :with_state
      end
      
      def self.with_states
        :with_states
      end
      
      def self.without_state
        :without_state
      end
      
      def self.without_states
        :without_states
      end
      
      def self.human_state_name
        :human_state_name
      end
      
      def self.human_state_event_name
        :human_state_event_name
      end
      
      attr_accessor :status
      
      def state
        'parked'
      end
      
      def state=(value)
        self.status = value
      end
      
      def state?
        true
      end
      
      def state_name
        :parked
      end
      
      def human_state_name
        'parked'
      end
      
      def state_events
        [:ignite]
      end
      
      def state_transitions
        [{:parked => :idling}]
      end
      
      def state_paths
        [[{:parked => :idling}]]
      end
      
      def fire_state_event
        true
      end
    end
    
    StateMachine::Integrations.const_set('Custom', Module.new do
      include StateMachine::Integrations::Base
      
      def create_with_scope(name)
        lambda {|klass, values| []}
      end
      
      def create_without_scope(name)
        lambda {|klass, values| []}
      end
    end)
    
    @machine = StateMachine::Machine.new(@klass, :integration => :custom)
    @machine.state :parked, :idling
    @machine.event :ignite
    @object = @klass.new
  end
  
  def test_should_not_redefine_singular_with_scope
    assert_equal :with_state, @klass.with_state
  end
  
  def test_should_not_redefine_plural_with_scope
    assert_equal :with_states, @klass.with_states
  end
  
  def test_should_not_redefine_singular_without_scope
    assert_equal :without_state, @klass.without_state
  end
  
  def test_should_not_redefine_plural_without_scope
    assert_equal :without_states, @klass.without_states
  end
  
  def test_should_not_redefine_human_attribute_name_reader
    assert_equal :human_state_name, @klass.human_state_name
  end
  
  def test_should_not_redefine_human_event_name_reader
    assert_equal :human_state_event_name, @klass.human_state_event_name
  end
  
  def test_should_not_redefine_attribute_writer
    assert_equal 'parked', @object.state
  end
  
  def test_should_not_redefine_attribute_writer
    @object.state = 'parked'
    assert_equal 'parked', @object.status
  end
  
  def test_should_not_define_attribute_predicate
    assert @object.state?
  end
  
  def test_should_not_redefine_attribute_name_reader
    assert_equal :parked, @object.state_name
  end
  
  def test_should_not_redefine_attribute_human_name_reader
    assert_equal 'parked', @object.human_state_name
  end
  
  def test_should_not_redefine_attribute_events_reader
    assert_equal [:ignite], @object.state_events
  end
  
  def test_should_not_redefine_attribute_transitions_reader
    assert_equal [{:parked => :idling}], @object.state_transitions
  end
  
  def test_should_not_redefine_attribute_paths_reader
    assert_equal [[{:parked => :idling}]], @object.state_paths
  end
  
  def test_should_not_redefine_event_runner
    assert_equal true, @object.fire_state_event
  end
  
  def test_should_allow_super_chaining
    @klass.class_eval do
      def self.with_state(*states)
        super
      end
      
      def self.with_states(*states)
        super
      end
      
      def self.without_state(*states)
        super
      end
      
      def self.without_states(*states)
        super
      end
      
      def self.human_state_name(state)
        super
      end
      
      def self.human_state_event_name(event)
        super
      end
      
      attr_accessor :status
      
      def state
        super
      end
      
      def state=(value)
        super
      end
      
      def state?(state)
        super
      end
      
      def state_name
        super
      end
      
      def human_state_name
        super
      end
      
      def state_events
        super
      end
      
      def state_transitions
        super
      end
      
      def state_paths
        super
      end
      
      def fire_state_event(event)
        super
      end
    end
    
    assert_equal [], @klass.with_state
    assert_equal [], @klass.with_states
    assert_equal [], @klass.without_state
    assert_equal [], @klass.without_states
    assert_equal 'parked', @klass.human_state_name(:parked)
    assert_equal 'ignite', @klass.human_state_event_name(:ignite)
    
    assert_equal nil, @object.state
    @object.state = 'idling'
    assert_equal 'idling', @object.state
    assert_equal nil, @object.status
    assert_equal false, @object.state?(:parked)
    assert_equal :idling, @object.state_name
    assert_equal 'idling', @object.human_state_name
    assert_equal [], @object.state_events
    assert_equal [], @object.state_transitions
    assert_equal [], @object.state_paths
    assert_equal false, @object.fire_state_event(:ignite)
  end
  
  def test_should_not_output_warning
    assert_equal '', $stderr.string
  end
  
  def teardown
    $stderr = @original_stderr
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class MachineWithSuperclassConflictingHelpersAfterDefinitionTest < Test::Unit::TestCase
  def setup
    require 'stringio'
    @original_stderr, $stderr = $stderr, StringIO.new
    
    @superclass = Class.new
    @klass = Class.new(@superclass)
    
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite
    
    @superclass.class_eval do
      def state?
        true
      end
    end
    
    @object = @klass.new
  end
  
  def test_should_call_superclass_attribute_predicate_without_arguments
    assert @object.state?
  end
  
  def test_should_define_attribute_predicate_with_arguments
    assert !@object.state?(:parked)
  end
  
  def teardown
    $stderr = @original_stderr
  end
end

class MachineWithoutInitializeTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @object = @klass.new
  end
  
  def test_should_initialize_state
    assert_equal 'parked', @object.state
  end
end

class MachineWithInitializeWithoutSuperTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def initialize
      end
    end
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @object = @klass.new
  end
  
  def test_should_not_initialize_state
    assert_nil @object.state
  end
end

class MachineWithInitializeAndSuperTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def initialize
        super()
      end
    end
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @object = @klass.new
  end
  
  def test_should_initialize_state
    assert_equal 'parked', @object.state
  end
end

class MachineWithInitializeArgumentsAndBlockTest < Test::Unit::TestCase
  def setup
    @superclass = Class.new do
      attr_reader :args
      attr_reader :block_given
      
      def initialize(*args)
        @args = args
        @block_given = block_given?
      end
    end
    @klass = Class.new(@superclass)
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @object = @klass.new(1, 2, 3) {}
  end
  
  def test_should_initialize_state
    assert_equal 'parked', @object.state
  end
  
  def test_should_preserve_arguments
    assert_equal [1, 2, 3], @object.args
  end
  
  def test_should_preserve_block
    assert @object.block_given
  end
end

class MachineWithCustomInitializeTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      def initialize
        initialize_state_machines
      end
    end
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @object = @klass.new
  end
  
  def test_should_initialize_state
    assert_equal 'parked', @object.state
  end
end

class MachinePersistenceTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_accessor :state_event
    end
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @object = @klass.new
  end
  
  def test_should_allow_reading_state
    assert_equal 'parked', @machine.read(@object, :state)
  end
  
  def test_should_allow_reading_custom_attributes
    assert_nil @machine.read(@object, :event)
    
    @object.state_event = 'ignite'
    assert_equal 'ignite', @machine.read(@object, :event)
  end
  
  def test_should_allow_reading_custom_instance_variables
    @klass.class_eval do
      attr_writer :state_value
    end
    
    @object.state_value = 1
    assert_raise(NoMethodError) { @machine.read(@object, :value) }
    assert_equal 1, @machine.read(@object, :value, true)
  end
  
  def test_should_allow_writing_state
    @machine.write(@object, :state, 'idling')
    assert_equal 'idling', @object.state
  end
  
  def test_should_allow_writing_custom_attributes
    @machine.write(@object, :event, 'ignite')
    assert_equal 'ignite', @object.state_event
  end
  
  def test_should_allow_writing_custom_instance_variables
    @klass.class_eval do
      attr_reader :state_value
    end
    
    assert_raise(NoMethodError) { @machine.write(@object, :value, 1) }
    assert_equal 1, @machine.write(@object, :value, 1, true)
    assert_equal 1, @object.state_value
  end
end


class MachineWithStatesTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @parked, @idling = @machine.state :parked, :idling
    
    @object = @klass.new
  end
  
  def test_should_have_states
    assert_equal [nil, :parked, :idling], @machine.states.map {|state| state.name}
  end
  
  def test_should_allow_state_lookup_by_name
    assert_equal @parked, @machine.states[:parked]
  end
  
  def test_should_allow_state_lookup_by_value
    assert_equal @parked, @machine.states['parked', :value]
  end
  
  def test_should_allow_human_state_name_lookup
    assert_equal 'parked', @klass.human_state_name(:parked)
  end
  
  def test_should_raise_exception_on_invalid_human_state_name_lookup
    exception = assert_raise(IndexError) {@klass.human_state_name(:invalid)}
    assert_equal ':invalid is an invalid name', exception.message
  end
  
  def test_should_use_stringified_name_for_value
    assert_equal 'parked', @parked.value
  end
  
  def test_should_not_use_custom_matcher
    assert_nil @parked.matcher
  end
  
  def test_should_raise_exception_if_invalid_option_specified
    exception = assert_raise(ArgumentError) {@machine.state(:first_gear, :invalid => true)}
    assert_equal 'Invalid key(s): invalid', exception.message
  end
  
  def test_should_raise_exception_if_conflicting_type_used_for_name
    exception = assert_raise(ArgumentError) { @machine.state 'first_gear' }
    assert_equal '"first_gear" state defined as String, :parked defined as Symbol; all states must be consistent', exception.message
  end
  
  def test_should_not_raise_exception_if_conflicting_type_is_nil_for_name
    assert_nothing_raised { @machine.state nil }
  end
end

class MachineWithStatesWithCustomValuesTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @state = @machine.state :parked, :value => 1
    
    @object = @klass.new
    @object.state = 1
  end
  
  def test_should_use_custom_value
    assert_equal 1, @state.value
  end
  
  def test_should_allow_lookup_by_custom_value
    assert_equal @state, @machine.states[1, :value]
  end
end

class MachineWithStatesWithCustomHumanNamesTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @state = @machine.state :parked, :human_name => 'stopped'
  end
  
  def test_should_use_custom_human_name
    assert_equal 'stopped', @state.human_name
  end
  
  def test_should_allow_human_state_name_lookup
    assert_equal 'stopped', @klass.human_state_name(:parked)
  end
end

class MachineWithStatesWithRuntimeDependenciesTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.state :parked
  end
  
  def test_should_not_evaluate_value_during_definition
    assert_nothing_raised { @machine.state :parked, :value => lambda {raise ArgumentError} }
  end
  
  def test_should_not_evaluate_if_not_initial_state
    @machine.state :parked, :value => lambda {raise ArgumentError}
    assert_nothing_raised { @klass.new }
  end
end

class MachineWithStateWithMatchersTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @state = @machine.state :parked, :if => lambda {|value| !value.nil?}
    
    @object = @klass.new
    @object.state = 1
  end
  
  def test_should_use_custom_matcher
    assert_not_nil @state.matcher
    assert @state.matches?(1)
    assert !@state.matches?(nil)
  end
end

class MachineWithCachedStateTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @state = @machine.state :parked, :value => lambda {Object.new}, :cache => true
    
    @object = @klass.new
  end
  
  def test_should_use_evaluated_value
    assert_instance_of Object, @object.state
  end
  
  def test_use_same_value_across_multiple_objects
    assert_equal @object.state, @klass.new.state
  end
end

class MachineWithStatesWithBehaviorsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    
    @parked, @idling = @machine.state :parked, :idling do
      def speed
        0
      end
    end
  end
  
  def test_should_define_behaviors_for_each_state
    assert_not_nil @parked.methods[:speed]
    assert_not_nil @idling.methods[:speed]
  end
  
  def test_should_define_different_behaviors_for_each_state
    assert_not_equal @parked.methods[:speed], @idling.methods[:speed]
  end
end

class MachineWithExistingStateTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @state = @machine.state :parked
    @same_state = @machine.state :parked, :value => 1
  end
  
  def test_should_not_create_a_new_state
    assert_same @state, @same_state
  end
  
  def test_should_update_attributes
    assert_equal 1, @state.value
  end
  
  def test_should_no_longer_be_able_to_look_up_state_by_original_value
    assert_nil @machine.states['parked', :value]
  end
  
  def test_should_be_able_to_look_up_state_by_new_value
    assert_equal @state, @machine.states[1, :value]
  end
end

class MachineWithStateMatchersTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
  end
  
  def test_should_empty_array_for_all_matcher
    assert_equal [], @machine.state(StateMachine::AllMatcher.instance)
  end
  
  def test_should_return_referenced_states_for_blacklist_matcher
    assert_instance_of StateMachine::State, @machine.state(StateMachine::BlacklistMatcher.new([:parked]))
  end
  
  def test_should_not_allow_configurations
    exception = assert_raise(ArgumentError) { @machine.state(StateMachine::BlacklistMatcher.new([:parked]), :human_name => 'Parked') }
    assert_equal 'Cannot configure states when using matchers (using {:human_name=>"Parked"})', exception.message
  end
  
  def test_should_track_referenced_states
    @machine.state(StateMachine::BlacklistMatcher.new([:parked]))
    assert_equal [nil, :parked], @machine.states.map {|state| state.name}
  end
  
  def test_should_eval_context_for_matching_states
    contexts_run = []
    @machine.event(StateMachine::BlacklistMatcher.new([:parked])) { contexts_run << self.name }
    
    @machine.event :parked
    assert_equal [], contexts_run
    
    @machine.event :idling
    assert_equal [:idling], contexts_run
    
    @machine.event :first_gear, :second_gear
    assert_equal [:idling, :first_gear, :second_gear], contexts_run
  end
end

class MachineWithOtherStates < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @parked, @idling = @machine.other_states(:parked, :idling)
  end
  
  def test_should_include_other_states_in_known_states
    assert_equal [@parked, @idling], @machine.states.to_a
  end
  
  def test_should_use_default_value
    assert_equal 'idling', @idling.value
  end
  
  def test_should_not_create_matcher
    assert_nil @idling.matcher
  end
end

class MachineWithEventsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
  end
  
  def test_should_return_the_created_event
    assert_instance_of StateMachine::Event, @machine.event(:ignite)
  end
  
  def test_should_create_event_with_given_name
    event = @machine.event(:ignite) {}
    assert_equal :ignite, event.name
  end
  
  def test_should_evaluate_block_within_event_context
    responded = false
    @machine.event :ignite do
      responded = respond_to?(:transition)
    end
    
    assert responded
  end
  
  def test_should_be_aliased_as_on
    event = @machine.on(:ignite) {}
    assert_equal :ignite, event.name
  end
  
  def test_should_have_events
    event = @machine.event(:ignite)
    assert_equal [event], @machine.events.to_a
  end
  
  def test_should_allow_human_state_name_lookup
    @machine.event(:ignite)
    assert_equal 'ignite', @klass.human_state_event_name(:ignite)
  end
  
  def test_should_raise_exception_on_invalid_human_state_event_name_lookup
    exception = assert_raise(IndexError) {@klass.human_state_event_name(:invalid)}
    assert_equal ':invalid is an invalid name', exception.message
  end
  
  def test_should_raise_exception_if_conflicting_type_used_for_name
    @machine.event :park
    exception = assert_raise(ArgumentError) {  @machine.event 'ignite' }
    assert_equal '"ignite" event defined as String, :park defined as Symbol; all events must be consistent', exception.message
  end
end

class MachineWithExistingEventTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @event = @machine.event(:ignite)
    @same_event = @machine.event(:ignite)
  end
  
  def test_should_not_create_new_event
    assert_same @event, @same_event
  end
  
  def test_should_allow_accessing_event_without_block
    assert_equal @event, @machine.event(:ignite)
  end
end

class MachineWithEventsWithCustomHumanNamesTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @event = @machine.event(:ignite, :human_name => 'start')
  end
  
  def test_should_use_custom_human_name
    assert_equal 'start', @event.human_name
  end
  
  def test_should_allow_human_state_name_lookup
    assert_equal 'start', @klass.human_state_event_name(:ignite)
  end
end

class MachineWithEventMatchersTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
  end
  
  def test_should_empty_array_for_all_matcher
    assert_equal [], @machine.event(StateMachine::AllMatcher.instance)
  end
  
  def test_should_return_referenced_events_for_blacklist_matcher
    assert_instance_of StateMachine::Event, @machine.event(StateMachine::BlacklistMatcher.new([:park]))
  end
  
  def test_should_not_allow_configurations
    exception = assert_raise(ArgumentError) { @machine.event(StateMachine::BlacklistMatcher.new([:park]), :human_name => 'Park') }
    assert_equal 'Cannot configure events when using matchers (using {:human_name=>"Park"})', exception.message
  end
  
  def test_should_track_referenced_events
    event = @machine.event(StateMachine::BlacklistMatcher.new([:park]))
    assert_equal [:park], @machine.events.map {|event| event.name}
  end
  
  def test_should_eval_context_for_matching_events
    contexts_run = []
    @machine.event(StateMachine::BlacklistMatcher.new([:park])) { contexts_run << self.name }
    
    @machine.event :park
    assert_equal [], contexts_run
    
    @machine.event :ignite
    assert_equal [:ignite], contexts_run
    
    @machine.event :shift_up, :shift_down
    assert_equal [:ignite, :shift_up, :shift_down], contexts_run
  end
end

class MachineWithEventsWithTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @event = @machine.event(:ignite) do
      transition :parked => :idling
      transition :stalled => :idling
    end
  end
  
  def test_should_have_events
    assert_equal [@event], @machine.events.to_a
  end
  
  def test_should_track_states_defined_in_event_transitions
    assert_equal [:parked, :idling, :stalled], @machine.states.map {|state| state.name}
  end
  
  def test_should_not_duplicate_states_defined_in_multiple_event_transitions
    @machine.event :park do
      transition :idling => :parked
    end
    
    assert_equal [:parked, :idling, :stalled], @machine.states.map {|state| state.name}
  end
  
  def test_should_track_state_from_new_events
    @machine.event :shift_up do
      transition :idling => :first_gear
    end
    
    assert_equal [:parked, :idling, :stalled, :first_gear], @machine.states.map {|state| state.name}
  end
end

class MachineWithMultipleEventsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @park, @shift_down = @machine.event(:park, :shift_down) do
      transition :first_gear => :parked
    end
  end
  
  def test_should_have_events
    assert_equal [@park, @shift_down], @machine.events.to_a
  end
  
  def test_should_define_transitions_for_each_event
    [@park, @shift_down].each {|event| assert_equal 1, event.branches.size}
  end
  
  def test_should_transition_the_same_for_each_event
    object = @klass.new
    object.state = 'first_gear'
    object.park
    assert_equal 'parked', object.state
    
    object = @klass.new
    object.state = 'first_gear'
    object.shift_down
    assert_equal 'parked', object.state
  end
end

class MachineWithTransitionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
  end
  
  def test_should_require_on_event
    exception = assert_raise(ArgumentError) { @machine.transition(:parked => :idling) }
    assert_equal 'Must specify :on event', exception.message
  end
  
  def test_should_not_allow_except_to_option
    exception = assert_raise(ArgumentError) {@machine.transition(:except_to => :parked, :on => :ignite)}
    assert_equal 'Invalid key(s): except_to', exception.message
  end
  
  def test_should_not_allow_except_on_option
    exception = assert_raise(ArgumentError) {@machine.transition(:except_on => :ignite, :on => :ignite)}
    assert_equal 'Invalid key(s): except_on', exception.message
  end
  
  def test_should_allow_transitioning_without_a_to_state
    assert_nothing_raised {@machine.transition(:from => :parked, :on => :ignite)}
  end
  
  def test_should_allow_transitioning_without_a_from_state
    assert_nothing_raised {@machine.transition(:to => :idling, :on => :ignite)}
  end
  
  def test_should_allow_except_from_option
    assert_nothing_raised {@machine.transition(:except_from => :idling, :on => :ignite)}
  end
  
  def test_should_allow_implicit_options
    branch = @machine.transition(:first_gear => :second_gear, :on => :shift_up)
    assert_instance_of StateMachine::Branch, branch
    
    state_requirements = branch.state_requirements
    assert_equal 1, state_requirements.length
    
    assert_instance_of StateMachine::WhitelistMatcher, state_requirements[0][:from]
    assert_equal [:first_gear], state_requirements[0][:from].values
    assert_instance_of StateMachine::WhitelistMatcher, state_requirements[0][:to]
    assert_equal [:second_gear], state_requirements[0][:to].values
    assert_instance_of StateMachine::WhitelistMatcher, branch.event_requirement
    assert_equal [:shift_up], branch.event_requirement.values
  end
  
  def test_should_allow_multiple_implicit_options
    branch = @machine.transition(:first_gear => :second_gear, :second_gear => :third_gear, :on => :shift_up)
    
    state_requirements = branch.state_requirements
    assert_equal 2, state_requirements.length
  end
  
  def test_should_allow_verbose_options
    branch = @machine.transition(:from => :parked, :to => :idling, :on => :ignite)
    assert_instance_of StateMachine::Branch, branch
  end
  
  def test_should_include_all_transition_states_in_machine_states
    @machine.transition(:parked => :idling, :on => :ignite)
    
    assert_equal [:parked, :idling], @machine.states.map {|state| state.name}
  end
  
  def test_should_include_all_transition_events_in_machine_events
    @machine.transition(:parked => :idling, :on => :ignite)
    
    assert_equal [:ignite], @machine.events.map {|event| event.name}
  end
  
  def test_should_allow_multiple_events
    branches = @machine.transition(:parked => :ignite, :on => [:ignite, :shift_up])
    
    assert_equal 2, branches.length
    assert_equal [:ignite, :shift_up], @machine.events.map {|event| event.name}
  end
  
  def test_should_not_modify_options
    options = {:parked => :idling, :on => :ignite}
    @machine.transition(options)
    
    assert_equal options, {:parked => :idling, :on => :ignite}
  end
end

class MachineWithTransitionCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_accessor :callbacks
    end
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @event = @machine.event :ignite do
      transition :parked => :idling
    end
    
    @object = @klass.new
    @object.callbacks = []
  end
  
  def test_should_not_raise_exception_if_implicit_option_specified
    assert_nothing_raised {@machine.before_transition :invalid => :valid, :do => lambda {}}
  end
  
  def test_should_raise_exception_if_method_not_specified
    exception = assert_raise(ArgumentError) {@machine.before_transition :to => :idling}
    assert_equal 'Method(s) for callback must be specified', exception.message
  end
  
  def test_should_invoke_callbacks_during_transition
    @machine.before_transition lambda {|object| object.callbacks << 'before'}
    @machine.after_transition lambda {|object| object.callbacks << 'after'}
    @machine.around_transition lambda {|object, transition, block| object.callbacks << 'before_around'; block.call; object.callbacks << 'after_around'}
    
    @event.fire(@object)
    assert_equal %w(before before_around after_around after), @object.callbacks
  end
  
  def test_should_allow_multiple_callbacks
    @machine.before_transition lambda {|object| object.callbacks << 'before1'}, lambda {|object| object.callbacks << 'before2'}
    @machine.after_transition lambda {|object| object.callbacks << 'after1'}, lambda {|object| object.callbacks << 'after2'}
    @machine.around_transition(
      lambda {|object, transition, block| object.callbacks << 'before_around1'; block.call; object.callbacks << 'after_around1'},
      lambda {|object, transition, block| object.callbacks << 'before_around2'; block.call; object.callbacks << 'after_around2'}
    )
    
    @event.fire(@object)
    assert_equal %w(before1 before2 before_around1 before_around2 after_around2 after_around1 after1 after2), @object.callbacks
  end
  
  def test_should_allow_multiple_callbacks_with_requirements
    @machine.before_transition lambda {|object| object.callbacks << 'before_parked1'}, lambda {|object| object.callbacks << 'before_parked2'}, :from => :parked
    @machine.before_transition lambda {|object| object.callbacks << 'before_idling1'}, lambda {|object| object.callbacks << 'before_idling2'}, :from => :idling
    @machine.after_transition lambda {|object| object.callbacks << 'after_parked1'}, lambda {|object| object.callbacks << 'after_parked2'}, :from => :parked
    @machine.after_transition lambda {|object| object.callbacks << 'after_idling1'}, lambda {|object| object.callbacks << 'after_idling2'}, :from => :idling
    @machine.around_transition(
      lambda {|object, transition, block| object.callbacks << 'before_around_parked1'; block.call; object.callbacks << 'after_around_parked1'},
      lambda {|object, transition, block| object.callbacks << 'before_around_parked2'; block.call; object.callbacks << 'after_around_parked2'},
      :from => :parked
    )
    @machine.around_transition(
      lambda {|object, transition, block| object.callbacks << 'before_around_idling1'; block.call; object.callbacks << 'after_around_idling1'},
      lambda {|object, transition, block| object.callbacks << 'before_around_idling2'; block.call; object.callbacks << 'after_around_idling2'},
      :from => :idling
    )
    
    @event.fire(@object)
    assert_equal %w(before_parked1 before_parked2 before_around_parked1 before_around_parked2 after_around_parked2 after_around_parked1 after_parked1 after_parked2), @object.callbacks
  end
  
  def test_should_support_from_requirement
    @machine.before_transition :from => :parked, :do => lambda {|object| object.callbacks << :parked}
    @machine.before_transition :from => :idling, :do => lambda {|object| object.callbacks << :idling}
    
    @event.fire(@object)
    assert_equal [:parked], @object.callbacks
  end
  
  def test_should_support_except_from_requirement
    @machine.before_transition :except_from => :parked, :do => lambda {|object| object.callbacks << :parked}
    @machine.before_transition :except_from => :idling, :do => lambda {|object| object.callbacks << :idling}
    
    @event.fire(@object)
    assert_equal [:idling], @object.callbacks
  end
  
  def test_should_support_to_requirement
    @machine.before_transition :to => :parked, :do => lambda {|object| object.callbacks << :parked}
    @machine.before_transition :to => :idling, :do => lambda {|object| object.callbacks << :idling}
    
    @event.fire(@object)
    assert_equal [:idling], @object.callbacks
  end
  
  def test_should_support_except_to_requirement
    @machine.before_transition :except_to => :parked, :do => lambda {|object| object.callbacks << :parked}
    @machine.before_transition :except_to => :idling, :do => lambda {|object| object.callbacks << :idling}
    
    @event.fire(@object)
    assert_equal [:parked], @object.callbacks
  end
  
  def test_should_support_on_requirement
    @machine.before_transition :on => :park, :do => lambda {|object| object.callbacks << :park}
    @machine.before_transition :on => :ignite, :do => lambda {|object| object.callbacks << :ignite}
    
    @event.fire(@object)
    assert_equal [:ignite], @object.callbacks
  end
  
  def test_should_support_except_on_requirement
    @machine.before_transition :except_on => :park, :do => lambda {|object| object.callbacks << :park}
    @machine.before_transition :except_on => :ignite, :do => lambda {|object| object.callbacks << :ignite}
    
    @event.fire(@object)
    assert_equal [:park], @object.callbacks
  end
  
  def test_should_support_implicit_requirement
    @machine.before_transition :parked => :idling, :do => lambda {|object| object.callbacks << :parked}
    @machine.before_transition :idling => :parked, :do => lambda {|object| object.callbacks << :idling}
    
    @event.fire(@object)
    assert_equal [:parked], @object.callbacks
  end
  
  def test_should_track_states_defined_in_transition_callbacks
    @machine.before_transition :parked => :idling, :do => lambda {}
    @machine.after_transition :first_gear => :second_gear, :do => lambda {}
    @machine.around_transition :third_gear => :fourth_gear, :do => lambda {}
    
    assert_equal [:parked, :idling, :first_gear, :second_gear, :third_gear, :fourth_gear], @machine.states.map {|state| state.name}
  end
  
  def test_should_not_duplicate_states_defined_in_multiple_event_transitions
    @machine.before_transition :parked => :idling, :do => lambda {}
    @machine.after_transition :first_gear => :second_gear, :do => lambda {}
    @machine.after_transition :parked => :idling, :do => lambda {}
    @machine.around_transition :parked => :idling, :do => lambda {}
    
    assert_equal [:parked, :idling, :first_gear, :second_gear], @machine.states.map {|state| state.name}
  end
  
  def test_should_define_predicates_for_each_state
    [:parked?, :idling?].each {|predicate| assert @object.respond_to?(predicate)}
  end
end

class MachineWithFailureCallbacksTest < Test::Unit::TestCase
  def setup
    @klass = Class.new do
      attr_accessor :callbacks
    end
    
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @event = @machine.event :ignite
    
    @object = @klass.new
    @object.callbacks = []
  end
  
  def test_should_raise_exception_if_implicit_option_specified
    exception = assert_raise(ArgumentError) {@machine.after_failure :invalid => :valid, :do => lambda {}}
    assert_equal 'Invalid key(s): invalid', exception.message
  end
  
  def test_should_raise_exception_if_method_not_specified
    exception = assert_raise(ArgumentError) {@machine.after_failure :on => :ignite}
    assert_equal 'Method(s) for callback must be specified', exception.message
  end
  
  def test_should_invoke_callbacks_during_failed_transition
    @machine.after_failure lambda {|object| object.callbacks << 'failure'}
    
    @event.fire(@object)
    assert_equal %w(failure), @object.callbacks
  end
  
  def test_should_allow_multiple_callbacks
    @machine.after_failure lambda {|object| object.callbacks << 'failure1'}, lambda {|object| object.callbacks << 'failure2'}
    
    @event.fire(@object)
    assert_equal %w(failure1 failure2), @object.callbacks
  end
  
  def test_should_allow_multiple_callbacks_with_requirements
    @machine.after_failure lambda {|object| object.callbacks << 'failure_ignite1'}, lambda {|object| object.callbacks << 'failure_ignite2'}, :on => :ignite
    @machine.after_failure lambda {|object| object.callbacks << 'failure_park1'}, lambda {|object| object.callbacks << 'failure_park2'}, :on => :park
    
    @event.fire(@object)
    assert_equal %w(failure_ignite1 failure_ignite2), @object.callbacks
  end
end

class MachineWithPathsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @machine.event :ignite do
      transition :parked => :idling
    end
    @machine.event :shift_up do
      transition :first_gear => :second_gear
    end
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_have_paths
    assert_equal [[StateMachine::Transition.new(@object, @machine, :ignite, :parked, :idling)]], @machine.paths_for(@object)
  end
  
  def test_should_allow_requirement_configuration
    assert_equal [[StateMachine::Transition.new(@object, @machine, :shift_up, :first_gear, :second_gear)]], @machine.paths_for(@object, :from => :first_gear)
  end
end

class MachineWithOwnerSubclassTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @subclass = Class.new(@klass)
  end
  
  def test_should_have_a_different_collection_of_state_machines
    assert_not_same @klass.state_machines, @subclass.state_machines
  end
  
  def test_should_have_the_same_attribute_associated_state_machines
    assert_equal @klass.state_machines, @subclass.state_machines
  end
end

class MachineWithExistingMachinesOnOwnerClassTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @second_machine = StateMachine::Machine.new(@klass, :status, :initial => :idling)
    @object = @klass.new
  end
  
  def test_should_track_each_state_machine
    expected = {:state => @machine, :status => @second_machine}
    assert_equal expected, @klass.state_machines
  end
  
  def test_should_initialize_state_for_both_machines
    assert_equal 'parked', @object.state
    assert_equal 'idling', @object.status
  end
end

class MachineWithExistingMachinesWithSameAttributesOnOwnerClassTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @second_machine = StateMachine::Machine.new(@klass, :public_state, :initial => :idling, :attribute => :state)
    @object = @klass.new
  end
  
  def test_should_track_each_state_machine
    expected = {:state => @machine, :public_state => @second_machine}
    assert_equal expected, @klass.state_machines
  end
  
  def test_should_write_to_state_only_once
    @klass.class_eval do
      attr_reader :write_count
      
      def state=(value)
        @write_count ||= 0
        @write_count += 1
      end
    end
    object = @klass.new
    
    assert_equal 1, object.write_count
  end
  
  def test_should_initialize_based_on_first_machine
    assert_equal 'parked', @object.state
  end
  
  def test_should_not_allow_second_machine_to_initialize_state
    @object.state = nil
    @second_machine.initialize_state(@object)
    assert_nil @object.state
  end
  
  def test_should_allow_transitions_on_both_machines
    @machine.event :ignite do
      transition :parked => :idling
    end
    
    @second_machine.event :park do
      transition :idling => :parked
    end
    
    @object.ignite
    assert_equal 'idling', @object.state
    
    @object.park
    assert_equal 'parked', @object.state
  end
  
  def test_should_copy_new_states_to_sibling_machines
    @first_gear = @machine.state :first_gear
    assert_equal @first_gear, @second_machine.state(:first_gear)
    
    @second_gear = @second_machine.state :second_gear
    assert_equal @second_gear, @machine.state(:second_gear)
  end
  
  def test_should_copy_all_existing_states_to_new_machines
    third_machine = StateMachine::Machine.new(@klass, :protected_state, :attribute => :state)
    
    assert_equal @machine.state(:parked), third_machine.state(:parked)
    assert_equal @machine.state(:idling), third_machine.state(:idling)
  end
end

class MachineWithExistingMachinesWithSameAttributesOnOwnerSubclassTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :initial => :parked)
    @second_machine = StateMachine::Machine.new(@klass, :public_state, :initial => :idling, :attribute => :state)
    
    @subclass = Class.new(@klass)
    @object = @subclass.new
  end
  
  def test_should_not_copy_sibling_machines_to_subclass_after_initialization
    @subclass.state_machine(:state) {}
    assert_equal @klass.state_machine(:public_state), @subclass.state_machine(:public_state)
  end
  
  def test_should_copy_sibling_machines_to_subclass_after_new_state
    subclass_machine = @subclass.state_machine(:state) {}
    subclass_machine.state :first_gear
    assert_not_equal @klass.state_machine(:public_state), @subclass.state_machine(:public_state)
  end
  
  def test_should_copy_new_states_to_sibling_machines
    subclass_machine = @subclass.state_machine(:state) {}
    @first_gear = subclass_machine.state :first_gear
    
    second_subclass_machine = @subclass.state_machine(:public_state)
    assert_equal @first_gear, second_subclass_machine.state(:first_gear)
  end
end

class MachineWithNamespaceTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :namespace => 'alarm', :initial => :active) do
      event :enable do
        transition :off => :active
      end
      
      event :disable do
        transition :active => :off
      end
    end
    @object = @klass.new
  end
  
  def test_should_namespace_state_predicates
    [:alarm_active?, :alarm_off?].each do |name|
      assert @object.respond_to?(name)
    end
  end
  
  def test_should_namespace_event_checks
    [:can_enable_alarm?, :can_disable_alarm?].each do |name|
      assert @object.respond_to?(name)
    end
  end
  
  def test_should_namespace_event_transition_readers
    [:enable_alarm_transition, :disable_alarm_transition].each do |name|
      assert @object.respond_to?(name)
    end
  end
  
  def test_should_namespace_events
    [:enable_alarm, :disable_alarm].each do |name|
      assert @object.respond_to?(name)
    end
  end
  
  def test_should_namespace_bang_events
    [:enable_alarm!, :disable_alarm!].each do |name|
      assert @object.respond_to?(name)
    end
  end
end

class MachineWithCustomAttributeTest < Test::Unit::TestCase
  def setup
    StateMachine::Integrations.const_set('Custom', Module.new do  
      include StateMachine::Integrations::Base
      
      @defaults = {:action => :save, :use_transactions => false}
      
      def create_with_scope(name)
        lambda {}
      end
      
      def create_without_scope(name)
        lambda {}
      end
    end)
    
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :state, :attribute => :state_id, :initial => :active, :integration => :custom) do
      event :ignite do
        transition :parked => :idling
      end
    end
    @object = @klass.new
  end
  
  def test_should_define_a_reader_attribute_for_the_attribute
    assert @object.respond_to?(:state_id)
  end
  
  def test_should_define_a_writer_attribute_for_the_attribute
    assert @object.respond_to?(:state_id=)
  end
  
  def test_should_define_a_predicate_for_the_attribute
    assert @object.respond_to?(:state?)
  end
  
  def test_should_define_a_name_reader_for_the_attribute
    assert @object.respond_to?(:state_name)
  end
  
  def test_should_define_a_human_name_reader_for_the_attribute
    assert @object.respond_to?(:state_name)
  end
  
  def test_should_define_an_event_reader_for_the_attribute
    assert @object.respond_to?(:state_events)
  end
  
  def test_should_define_a_transition_reader_for_the_attribute
    assert @object.respond_to?(:state_transitions)
  end
  
  def test_should_define_a_path_reader_for_the_attribute
    assert @object.respond_to?(:state_paths)
  end
  
  def test_should_define_an_event_runner_for_the_attribute
    assert @object.respond_to?(:fire_state_event)
  end
  
  def test_should_define_a_human_attribute_name_reader
    assert @klass.respond_to?(:human_state_name)
  end
  
  def test_should_define_a_human_event_name_reader
    assert @klass.respond_to?(:human_state_event_name)
  end
  
  def test_should_define_singular_with_scope
    assert @klass.respond_to?(:with_state)
  end
  
  def test_should_define_singular_without_scope
    assert @klass.respond_to?(:without_state)
  end
  
  def test_should_define_plural_with_scope
    assert @klass.respond_to?(:with_states)
  end
  
  def test_should_define_plural_without_scope
    assert @klass.respond_to?(:without_states)
  end
  
  def test_should_define_state_machines_reader
    expected = {:state => @machine}
    assert_equal expected, @klass.state_machines
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class MachineFinderWithoutExistingMachineTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.find_or_create(@klass)
  end
  
  def test_should_accept_a_block
    called = false
    StateMachine::Machine.find_or_create(Class.new) do
      called = respond_to?(:event)
    end
    
    assert called
  end
  
  def test_should_create_a_new_machine
    assert_not_nil @machine
  end
  
  def test_should_use_default_state
    assert_equal :state, @machine.attribute
  end
end

class MachineFinderWithExistingOnSameClassTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @existing_machine = StateMachine::Machine.new(@klass)
    @machine = StateMachine::Machine.find_or_create(@klass)
  end
  
  def test_should_accept_a_block
    called = false
    StateMachine::Machine.find_or_create(@klass) do
      called = respond_to?(:event)
    end
    
    assert called
  end
  
  def test_should_not_create_a_new_machine
    assert_same @machine, @existing_machine
  end
end

class MachineFinderWithExistingMachineOnSuperclassTest < Test::Unit::TestCase
  def setup
    integration = Module.new do
      include StateMachine::Integrations::Base
      
      def self.matches?(klass)
        false
      end
    end
    StateMachine::Integrations.const_set('Custom', integration)
    
    @base_class = Class.new
    @base_machine = StateMachine::Machine.new(@base_class, :status, :action => :save, :integration => :custom)
    @base_machine.event(:ignite) {}
    @base_machine.before_transition(lambda {})
    @base_machine.after_transition(lambda {})
    @base_machine.around_transition(lambda {})
    
    @klass = Class.new(@base_class)
    @machine = StateMachine::Machine.find_or_create(@klass, :status) {}
  end
  
  def test_should_accept_a_block
    called = false
    StateMachine::Machine.find_or_create(Class.new(@base_class)) do
      called = respond_to?(:event)
    end
    
    assert called
  end
  
  def test_should_not_create_a_new_machine_if_no_block_or_options
    machine = StateMachine::Machine.find_or_create(Class.new(@base_class), :status)
    
    assert_same machine, @base_machine
  end
  
  def test_should_create_a_new_machine_if_given_options
    machine = StateMachine::Machine.find_or_create(@klass, :status, :initial => :parked)
    
    assert_not_nil machine
    assert_not_same machine, @base_machine
  end
  
  def test_should_create_a_new_machine_if_given_block
    assert_not_nil @machine
    assert_not_same @machine, @base_machine
  end
  
  def test_should_copy_the_base_attribute
    assert_equal :status, @machine.attribute
  end
  
  def test_should_copy_the_base_configuration
    assert_equal :save, @machine.action
  end
  
  def test_should_copy_events
    # Can't assert equal arrays since their machines change
    assert_equal 1, @machine.events.length
  end
  
  def test_should_copy_before_callbacks
    assert_equal @base_machine.callbacks[:before], @machine.callbacks[:before]
  end
  
  def test_should_copy_after_transitions
    assert_equal @base_machine.callbacks[:after], @machine.callbacks[:after]
  end
  
  def test_should_use_the_same_integration
    assert (class << @machine; ancestors; end).include?(StateMachine::Integrations::Custom)
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end

class MachineFinderCustomOptionsTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.find_or_create(@klass, :status, :initial => :parked)
    @object = @klass.new
  end
  
  def test_should_use_custom_attribute
    assert_equal :status, @machine.attribute
  end
  
  def test_should_set_custom_initial_state
    assert_equal :parked, @machine.initial_state(@object).name
  end
end

begin
  # Load library
  require 'graphviz'
  
  class MachineDrawingTest < Test::Unit::TestCase
    def setup
      @klass = Class.new do
        def self.name; 'Vehicle'; end
      end
      @machine = StateMachine::Machine.new(@klass, :initial => :parked)
      @machine.event :ignite do
        transition :parked => :idling
      end
    end
    
    def test_should_raise_exception_if_invalid_option_specified
      assert_raise(ArgumentError) {@machine.draw(:invalid => true)}
    end
    
    def test_should_save_file_with_class_name_by_default
      graph = @machine.draw
      assert File.exists?('./Vehicle_state.png')
    end
    
    def test_should_allow_base_name_to_be_customized
      graph = @machine.draw(:name => 'machine')
      assert File.exists?('./machine.png')
    end
    
    def test_should_allow_format_to_be_customized
      graph = @machine.draw(:format => 'jpg')
      assert File.exists?('./Vehicle_state.jpg')
    end
    
    def test_should_allow_path_to_be_customized
      graph = @machine.draw(:path => "#{File.dirname(__FILE__)}/")
      assert File.exists?("#{File.dirname(__FILE__)}/Vehicle_state.png")
    end
    
    def test_should_allow_orientation_to_be_landscape
      graph = @machine.draw(:orientation => 'landscape')
      assert_equal 'LR', graph['rankdir'].to_s.gsub('"', '')
    end
    
    def test_should_allow_orientation_to_be_portrait
      graph = @machine.draw(:orientation => 'portrait')
      assert_equal 'TB', graph['rankdir'].to_s.gsub('"', '')
    end
    
    if Constants::RGV_VERSION != '0.9.0'
      def test_should_allow_human_names_to_be_displayed
        @machine.event :ignite, :human_name => 'Ignite'
        @machine.state :parked, :human_name => 'Parked'
        @machine.state :idling, :human_name => 'Idling'
        graph = @machine.draw(:human_names => true)
        
        parked_node = graph.get_node('parked')
        assert_equal 'Parked', parked_node['label'].to_s.gsub('"', '')
        
        idling_node = graph.get_node('idling')
        assert_equal 'Idling', idling_node['label'].to_s.gsub('"', '')
      end
    end
    
    def teardown
      FileUtils.rm Dir["{.,#{File.dirname(__FILE__)}}/*.{png,jpg}"]
    end
  end
  
  class MachineDrawingWithIntegerStatesTest < Test::Unit::TestCase
    def setup
      @klass = Class.new do
        def self.name; 'Vehicle'; end
      end
      @machine = StateMachine::Machine.new(@klass, :state_id, :initial => :parked)
      @machine.event :ignite do
        transition :parked => :idling
      end
      @machine.state :parked, :value => 1
      @machine.state :idling, :value => 2
      @graph = @machine.draw
    end
    
    def test_should_draw_all_states
      assert_equal 3, @graph.node_count
    end
    
    def test_should_draw_all_events
      assert_equal 2, @graph.edge_count
    end
    
    def test_should_draw_machine
      assert File.exist?('./Vehicle_state_id.png')
    ensure
      FileUtils.rm('./Vehicle_state_id.png')
    end
  end
  
  class MachineDrawingWithNilStatesTest < Test::Unit::TestCase
    def setup
      @klass = Class.new do
        def self.name; 'Vehicle'; end
      end
      @machine = StateMachine::Machine.new(@klass, :initial => :parked)
      @machine.event :ignite do
        transition :parked => :idling
      end
      @machine.state :parked, :value => nil
      @graph = @machine.draw
    end
    
    def test_should_draw_all_states
      assert_equal 3, @graph.node_count
    end
    
    def test_should_draw_all_events
      assert_equal 2, @graph.edge_count
    end
    
    def test_should_draw_machine
      assert File.exist?('./Vehicle_state.png')
    ensure
      FileUtils.rm('./Vehicle_state.png')
    end
  end
  
  class MachineDrawingWithDynamicStatesTest < Test::Unit::TestCase
    def setup
      @klass = Class.new do
        def self.name; 'Vehicle'; end
      end
      @machine = StateMachine::Machine.new(@klass, :initial => :parked)
      @machine.event :activate do
        transition :parked => :idling
      end
      @machine.state :idling, :value => lambda {Time.now}
      @graph = @machine.draw
    end
    
    def test_should_draw_all_states
      assert_equal 3, @graph.node_count
    end
    
    def test_should_draw_all_events
      assert_equal 2, @graph.edge_count
    end
    
    def test_should_draw_machine
      assert File.exist?('./Vehicle_state.png')
    ensure
      FileUtils.rm('./Vehicle_state.png')
    end
  end
  
  class MachineClassDrawingTest < Test::Unit::TestCase
    def setup
      @klass = Class.new do
        def self.name; 'Vehicle'; end
      end
      @machine = StateMachine::Machine.new(@klass)
      @machine.event :ignite do
        transition :parked => :idling
      end
    end
    
    def test_should_raise_exception_if_no_class_names_specified
      exception = assert_raise(ArgumentError) {StateMachine::Machine.draw(nil)}
      assert_equal 'At least one class must be specified', exception.message
    end
    
    def test_should_load_files
      StateMachine::Machine.draw('Switch', :file => File.expand_path("#{File.dirname(__FILE__)}/../files/switch.rb"))
      assert defined?(::Switch)
    ensure
      FileUtils.rm('./Switch_state.png')
    end
    
    def test_should_allow_path_and_format_to_be_customized
      StateMachine::Machine.draw('Switch', :file => File.expand_path("#{File.dirname(__FILE__)}/../files/switch.rb"), :path => "#{File.dirname(__FILE__)}/", :format => 'jpg')
      assert File.exist?("#{File.dirname(__FILE__)}/Switch_state.jpg")
    ensure
      FileUtils.rm("#{File.dirname(__FILE__)}/Switch_state.jpg")
    end
  end
rescue LoadError
  $stderr.puts 'Skipping GraphViz StateMachine::Machine tests. `gem install ruby-graphviz` >= v0.9.0 and try again.'
end unless ENV['TRAVIS']
