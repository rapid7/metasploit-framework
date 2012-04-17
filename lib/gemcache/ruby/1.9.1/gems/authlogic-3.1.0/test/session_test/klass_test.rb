require 'test_helper'

module SessionTest
  module KlassTest
    class ConfigTest < ActiveSupport::TestCase
      def test_authenticate_with
        UserSession.authenticate_with = Employee
        assert_equal "Employee", UserSession.klass_name
        assert_equal Employee, UserSession.klass

        UserSession.authenticate_with User
        assert_equal "User", UserSession.klass_name
        assert_equal User, UserSession.klass
      end

      def test_klass
        assert_equal User, UserSession.klass
      end

      def test_klass_name
        assert_equal "User", UserSession.klass_name
      end

      def test_klass_name_uses_custom_name
        assert_equal "User", UserSession.klass_name
        assert_equal "BackOfficeUser", BackOfficeUserSession.klass_name
      end
    end

    class InstanceMethodsTest < ActiveSupport::TestCase
      def test_record_method
        ben = users(:ben)
        set_session_for(ben)
        session = UserSession.find
        assert_equal ben, session.record
        assert_equal ben, session.user
      end
    end
  end
end