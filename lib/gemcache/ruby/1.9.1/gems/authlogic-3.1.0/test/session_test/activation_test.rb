require 'test_helper'

module SessionTest
  module ActivationTest
    class ClassMethodsTest < ActiveSupport::TestCase
      def test_activated
        assert UserSession.activated?
        Authlogic::Session::Base.controller = nil
        assert !UserSession.activated?
      end
    
      def test_controller
        Authlogic::Session::Base.controller = nil
        assert_nil Authlogic::Session::Base.controller
        thread1 = Thread.new do
          controller = MockController.new
          Authlogic::Session::Base.controller = controller
          assert_equal controller, Authlogic::Session::Base.controller
        end
        thread1.join

        assert_nil Authlogic::Session::Base.controller
      
        thread2 = Thread.new do
          controller = MockController.new
          Authlogic::Session::Base.controller = controller
          assert_equal controller, Authlogic::Session::Base.controller
        end
        thread2.join
      
        assert_nil Authlogic::Session::Base.controller
      end
    end
    
    class InstanceMethodsTest < ActiveSupport::TestCase
      def test_init
        UserSession.controller = nil
        assert_raise(Authlogic::Session::Activation::NotActivatedError) { UserSession.new }
        UserSession.controller = controller
      end
    end
  end
end