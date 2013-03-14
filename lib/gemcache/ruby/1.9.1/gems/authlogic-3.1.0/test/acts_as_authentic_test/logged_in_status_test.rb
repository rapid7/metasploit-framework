require 'test_helper'

module ActsAsAuthenticTest
  class LoggedInStatusTest < ActiveSupport::TestCase
    def test_logged_in_timeout_config
      assert_equal 10.minutes.to_i, User.logged_in_timeout
      assert_equal 10.minutes.to_i, Employee.logged_in_timeout
      
      User.logged_in_timeout = 1.hour
      assert_equal 1.hour.to_i, User.logged_in_timeout
      User.logged_in_timeout 10.minutes
      assert_equal 10.minutes.to_i, User.logged_in_timeout
    end
    
    def test_named_scope_logged_in
      assert_equal 0, User.logged_in.count
      User.first.update_attribute(:last_request_at, Time.now)
      assert_equal 1, User.logged_in.count
    end
    
    def test_named_scope_logged_out
      assert_equal 2, User.logged_out.count
      User.first.update_attribute(:last_request_at, Time.now)
      assert_equal 1, User.logged_out.count
    end
    
    def test_logged_in_logged_out
      u = User.first
      assert !u.logged_in?
      assert u.logged_out?
      u.last_request_at = Time.now
      assert u.logged_in?
      assert !u.logged_out?
    end
  end
end