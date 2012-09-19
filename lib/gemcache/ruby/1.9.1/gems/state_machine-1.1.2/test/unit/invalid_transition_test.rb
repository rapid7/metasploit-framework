require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class InvalidTransitionTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @state = @machine.state :parked
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
    
    @invalid_transition = StateMachine::InvalidTransition.new(@object, @machine, :ignite)
  end
  
  def test_should_have_an_object
    assert_equal @object, @invalid_transition.object
  end
  
  def test_should_have_a_machine
    assert_equal @machine, @invalid_transition.machine
  end
  
  def test_should_have_an_event
    assert_equal :ignite, @invalid_transition.event
  end
  
  def test_should_have_a_qualified_event
    assert_equal :ignite, @invalid_transition.qualified_event
  end
  
  def test_should_have_a_from_value
    assert_equal 'parked', @invalid_transition.from
  end
  
  def test_should_have_a_from_name
    assert_equal :parked, @invalid_transition.from_name
  end
  
  def test_should_have_a_qualified_from_name
    assert_equal :parked, @invalid_transition.qualified_from_name
  end
  
  def test_should_generate_a_message
    assert_equal 'Cannot transition state via :ignite from :parked', @invalid_transition.message
  end
end

class InvalidTransitionWithNamespaceTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass, :namespace => 'alarm')
    @state = @machine.state :active
    @machine.event :disable
    
    @object = @klass.new
    @object.state = 'active'
    
    @invalid_transition = StateMachine::InvalidTransition.new(@object, @machine, :disable)
  end
  
  def test_should_have_an_event
    assert_equal :disable, @invalid_transition.event
  end
  
  def test_should_have_a_qualified_event
    assert_equal :disable_alarm, @invalid_transition.qualified_event
  end
  
  def test_should_have_a_from_name
    assert_equal :active, @invalid_transition.from_name
  end
  
  def test_should_have_a_qualified_from_name
    assert_equal :alarm_active, @invalid_transition.qualified_from_name
  end
end

class InvalidTransitionWithIntegrationTest < Test::Unit::TestCase
  def setup
    StateMachine::Integrations.const_set('Custom', Module.new do
      include StateMachine::Integrations::Base
      
      def errors_for(object)
        object.errors
      end
    end)
    
    @klass = Class.new do
      attr_accessor :errors
    end
    @machine = StateMachine::Machine.new(@klass, :integration => :custom)
    @machine.state :parked
    @machine.event :ignite
    
    @object = @klass.new
    @object.state = 'parked'
  end
  
  def test_should_generate_a_message_without_reasons_if_empty
    @object.errors = ''
    invalid_transition = StateMachine::InvalidTransition.new(@object, @machine, :ignite)
    assert_equal 'Cannot transition state via :ignite from :parked', invalid_transition.message
  end
  
  def test_should_generate_a_message_with_error_reasons_if_errors_found
    @object.errors = 'Id is invalid, Name is invalid'
    invalid_transition = StateMachine::InvalidTransition.new(@object, @machine, :ignite)
    assert_equal 'Cannot transition state via :ignite from :parked (Reason(s): Id is invalid, Name is invalid)', invalid_transition.message
  end
  
  def teardown
    StateMachine::Integrations.send(:remove_const, 'Custom')
  end
end
