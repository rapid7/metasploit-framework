require 'test_helper'

module SessionTest
  module TimeoutTest
    class ConfigTest < ActiveSupport::TestCase
      def test_logout_on_timeout
        UserSession.logout_on_timeout = true
        assert UserSession.logout_on_timeout
    
        UserSession.logout_on_timeout false
        assert !UserSession.logout_on_timeout
      end
    end
    
    class InstanceMethods < ActiveSupport::TestCase
      def test_stale_state
        UserSession.logout_on_timeout = true
        ben = users(:ben)
        ben.last_request_at = 3.years.ago
        ben.save
        set_session_for(ben)
      
        session = UserSession.new
        assert session.persisting?
        assert session.stale?
        assert_equal ben, session.stale_record
        assert_nil session.record
        assert_nil controller.session["user_credentials_id"]
      
        set_session_for(ben)
      
        ben.last_request_at = Time.now
        ben.save
      
        assert session.persisting?
        assert !session.stale?
        assert_nil session.stale_record
      
        UserSession.logout_on_timeout = false
      end
      
      def test_successful_login
        UserSession.logout_on_timeout = true
        ben = users(:ben)
        assert UserSession.create(:login => ben.login, :password => "benrocks")
        assert session = UserSession.find
        assert_equal ben, session.record
        UserSession.logout_on_timeout = false
      end
    end
  end
end