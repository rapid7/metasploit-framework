require 'test_helper'

module ActsAsAuthenticTest
  class SingleAccessTest < ActiveSupport::TestCase
    def test_change_single_access_token_with_password_config
      assert !User.change_single_access_token_with_password
      assert !Employee.change_single_access_token_with_password
      
      User.change_single_access_token_with_password = true
      assert User.change_single_access_token_with_password
      User.change_single_access_token_with_password false
      assert !User.change_single_access_token_with_password
    end
    
    def test_validates_uniqueness_of_single_access_token
      u = User.new
      u.single_access_token = users(:ben).single_access_token
      assert !u.valid?
      assert u.errors[:single_access_token].size > 0
    end
    
    def test_before_validation_reset_single_access_token
      u = User.new
      assert !u.valid?
      assert_not_nil u.single_access_token
    end
    
    def test_after_password_set_reset_single_access_token
      User.change_single_access_token_with_password = true
      
      ben = users(:ben)
      old_single_access_token = ben.single_access_token
      ben.password = "new_pass"
      assert_not_equal old_single_access_token, ben.single_access_token
      
      User.change_single_access_token_with_password = false
    end
    
    def test_after_password_set_is_not_called
      ldaper = Ldaper.new
      assert ldaper.save
    end
  end
end