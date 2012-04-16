require File.expand_path(File.dirname(__FILE__) + '/../../test_helper')

# Load library
require 'rubygems'

module BaseTest  
  class IntegrationTest < Test::Unit::TestCase
    def test_should_have_an_integration_name
      assert_equal :base, StateMachine::Integrations::Base.integration_name
    end
    
    def test_should_not_be_available
      assert !StateMachine::Integrations::Base.available?
    end
    
    def test_should_not_have_any_matching_ancestors
      assert_equal [], StateMachine::Integrations::Base.matching_ancestors
    end
    
    def test_should_not_match_any_classes
      assert !StateMachine::Integrations::Base.matches?(Class.new)
    end
    
    def test_should_not_have_a_locale_path
      assert_nil StateMachine::Integrations::Base.locale_path
    end
  end
  
  class IncludedTest < Test::Unit::TestCase
    def setup
      @integration = Module.new
      StateMachine::Integrations.const_set('Custom', @integration)
      
      @integration.class_eval do
        include StateMachine::Integrations::Base
      end
    end
    
    def test_should_not_have_any_defaults
      assert_nil @integration.defaults
    end
    
    def test_should_not_have_any_versions
      assert_equal [], @integration.versions
    end
    
    def test_should_track_version
      version1 = @integration.version '1.0' do
        def self.active?
          true
        end
      end
      
      version2 = @integration.version '2.0' do
        def self.active?
          false
        end
      end
      
      assert_equal [version1, version2], @integration.versions
    end
    
    def test_should_allow_active_versions_to_override_default_behavior
      @integration.class_eval do
        def version1_included?
          false
        end
        
        def version2_included?
          false
        end
      end
      
      version1 = @integration.version '1.0' do
        def self.active?
          true
        end
        
        def version1_included?
          true
        end
      end
      
      version2 = @integration.version '2.0' do
        def self.active?
          false
        end
        
        def version2_included?
          true
        end
      end
      
      @machine = StateMachine::Machine.new(Class.new, :integration => :custom)
      assert @machine.version1_included?
      assert !@machine.version2_included?
    end
    
    def teardown
      StateMachine::Integrations.send(:remove_const, 'Custom')
    end
  end
end
