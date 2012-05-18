require 'test_helper'

module SessionTest
  class HttpAuthTest < ActiveSupport::TestCase
    class ConfiTest < ActiveSupport::TestCase
      def test_allow_http_basic_auth
        UserSession.allow_http_basic_auth = false
        assert_equal false, UserSession.allow_http_basic_auth
    
        UserSession.allow_http_basic_auth true
        assert_equal true, UserSession.allow_http_basic_auth
      end

      def test_request_http_basic_auth
        UserSession.request_http_basic_auth = true
        assert_equal true, UserSession.request_http_basic_auth

        UserSession.request_http_basic_auth = false
        assert_equal false, UserSession.request_http_basic_auth
      end

      def test_http_basic_auth_realm
        assert_equal 'Application', UserSession.http_basic_auth_realm

        UserSession.http_basic_auth_realm = 'TestRealm'
        assert_equal 'TestRealm', UserSession.http_basic_auth_realm
      end
    end
    
    class InstanceMethodsTest < ActiveSupport::TestCase
      def test_persist_persist_by_http_auth
        ben = users(:ben)
        http_basic_auth_for do
          assert !UserSession.find
        end
        http_basic_auth_for(ben) do
          assert session = UserSession.find
          assert_equal ben, session.record
          assert_equal ben.login, session.login
          assert_equal "benrocks", session.send(:protected_password)
          assert !controller.http_auth_requested?
        end
        unset_session
        UserSession.request_http_basic_auth = true
        UserSession.http_basic_auth_realm = 'PersistTestRealm'
        http_basic_auth_for(ben) do
          assert session = UserSession.find
          assert_equal ben, session.record
          assert_equal ben.login, session.login
          assert_equal "benrocks", session.send(:protected_password)
          assert_equal 'PersistTestRealm', controller.realm
          assert controller.http_auth_requested?
        end
      end
    end
  end
end
