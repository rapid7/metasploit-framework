require 'test_helper'

module SessionTest
  module SessionTest
    class ConfigTest < ActiveSupport::TestCase
      def test_session_key
        UserSession.session_key = "my_session_key"
        assert_equal "my_session_key", UserSession.session_key
    
        UserSession.session_key "user_credentials"
        assert_equal "user_credentials", UserSession.session_key
      end
    end
    
    class InstanceMethodsTest < ActiveSupport::TestCase
      def test_persist_persist_by_session
        ben = users(:ben)
        set_session_for(ben)
        assert session = UserSession.find
        assert_equal ben, session.record
        assert_equal ben.persistence_token, controller.session["user_credentials"]
      end
      
      def test_persist_persist_by_session_with_token_only
        ben = users(:ben)
        set_session_for(ben)
        controller.session["user_credentials_id"] = nil
        assert session = UserSession.find
        assert_equal ben, session.record
        assert_equal ben.persistence_token, controller.session["user_credentials"]
      end
    
      def test_after_save_update_session
        ben = users(:ben)
        session = UserSession.new(ben)
        assert controller.session["user_credentials"].blank?
        assert session.save
        assert_equal ben.persistence_token, controller.session["user_credentials"]
      end
    
      def test_after_destroy_update_session
        ben = users(:ben)
        set_session_for(ben)
        assert_equal ben.persistence_token, controller.session["user_credentials"]
        assert session = UserSession.find
        assert session.destroy
        assert controller.session["user_credentials"].blank?
      end
    
      def test_after_persisting_update_session
        ben = users(:ben)
        set_cookie_for(ben)
        assert controller.session["user_credentials"].blank?
        assert UserSession.find
        assert_equal ben.persistence_token, controller.session["user_credentials"]
      end
    end
  end
end