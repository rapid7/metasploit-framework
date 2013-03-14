require 'test_helper'

module ActsAsAuthenticTest
  class PersistenceTokenTest < ActiveSupport::TestCase
    def test_after_password_set_reset_persistence_token
      ben = users(:ben)
      old_persistence_token = ben.persistence_token
      ben.password = "newpass"
      assert_not_equal old_persistence_token, ben.persistence_token
    end
    
    def test_after_password_verification_reset_persistence_token
      ben = users(:ben)
      old_persistence_token = ben.persistence_token
      assert ben.valid_password?(password_for(ben))
      assert_equal old_persistence_token, ben.persistence_token
      
      # only update it if it is nil
      assert ben.update_attribute(:persistence_token, nil)
      assert ben.valid_password?(password_for(ben))
      assert_not_equal old_persistence_token, ben.persistence_token
    end
    
    def test_before_validate_reset_persistence_token
      u = User.new
      assert !u.valid?
      assert_not_nil u.persistence_token
    end
    
    def test_forget_all
      http_basic_auth_for(users(:ben)) { UserSession.find }
      http_basic_auth_for(users(:zack)) { UserSession.find(:ziggity_zack) }
      assert UserSession.find
      assert UserSession.find(:ziggity_zack)
      User.forget_all
      assert !UserSession.find
      assert !UserSession.find(:ziggity_zack)
    end
    
    def test_forget
      ben = users(:ben)
      zack = users(:zack)
      http_basic_auth_for(ben) { UserSession.find }
      http_basic_auth_for(zack) { UserSession.find(:ziggity_zack) }

      assert ben.reload.logged_in?
      assert zack.reload.logged_in?

      ben.forget!

      assert !UserSession.find
      assert UserSession.find(:ziggity_zack)
    end
  end
end