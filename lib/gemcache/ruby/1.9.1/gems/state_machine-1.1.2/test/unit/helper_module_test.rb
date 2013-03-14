require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class HelperModuleTest < Test::Unit::TestCase
  def setup
    @klass = Class.new
    @machine = StateMachine::Machine.new(@klass)
    @helper_module = StateMachine::HelperModule.new(@machine, :instance)
  end
  
  def test_should_not_have_a_name
    assert_equal '', @helper_module.name.to_s
  end
  
  def test_should_provide_human_readable_to_s
    assert_equal "#{@klass} :state instance helpers", @helper_module.to_s
  end
end
