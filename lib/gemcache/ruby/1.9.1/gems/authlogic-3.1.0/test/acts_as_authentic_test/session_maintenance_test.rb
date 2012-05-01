require 'test_helper'

module ActsAsAuthenticTest
  class SessionMaintenanceTest < ActiveSupport::TestCase
    def test_maintain_sessions_config
      assert User.maintain_sessions
      User.maintain_sessions = false
      assert !User.maintain_sessions
      User.maintain_sessions true
      assert User.maintain_sessions
    end
    
    def test_login_after_create
      assert User.create(:login => "awesome", :password => "saweet", :password_confirmation => "saweet", :email => "awesome@awesome.com")
      assert UserSession.find
    end
    
    def test_updating_session_with_failed_magic_state
      ben = users(:ben)
      ben.confirmed = false
      ben.password = "newpass"
      ben.password_confirmation = "newpass"
      assert ben.save
    end

    def test_update_session_after_password_modify
      ben = users(:ben)
      UserSession.create(ben)
      old_session_key = controller.session["user_credentials"]
      old_cookie_key = controller.cookies["user_credentials"]
      ben.password = "newpass"
      ben.password_confirmation = "newpass"
      assert ben.save
      assert controller.session["user_credentials"]
      assert controller.cookies["user_credentials"]
      assert_not_equal controller.session["user_credentials"], old_session_key
      assert_not_equal controller.cookies["user_credentials"], old_cookie_key
    end

    def test_no_session_update_after_modify
      ben = users(:ben)
      UserSession.create(ben)
      old_session_key = controller.session["user_credentials"]
      old_cookie_key = controller.cookies["user_credentials"]
      ben.first_name = "Ben"
      assert ben.save
      assert_equal controller.session["user_credentials"], old_session_key
      assert_equal controller.cookies["user_credentials"], old_cookie_key
    end
    
    def test_creating_other_user
      ben = users(:ben)
      UserSession.create(ben)
      old_session_key = controller.session["user_credentials"]
      old_cookie_key = controller.cookies["user_credentials"]
      assert User.create(:login => "awesome", :password => "saweet", :password_confirmation => "saweet", :email => "awesome@saweet.com")
      assert_equal controller.session["user_credentials"], old_session_key
      assert_equal controller.cookies["user_credentials"], old_cookie_key
    end

    def test_updating_other_user
      ben = users(:ben)
      UserSession.create(ben)
      old_session_key = controller.session["user_credentials"]
      old_cookie_key = controller.cookies["user_credentials"]
      zack = users(:zack)
      zack.password = "newpass"
      zack.password_confirmation = "newpass"
      assert zack.save
      assert_equal controller.session["user_credentials"], old_session_key
      assert_equal controller.cookies["user_credentials"], old_cookie_key
    end

    def test_resetting_password_when_logged_out
      ben = users(:ben)
      assert !UserSession.find
      ben.password = "newpass"
      ben.password_confirmation = "newpass"
      assert ben.save
      assert UserSession.find
      assert_equal ben, UserSession.find.record
    end
  end
end