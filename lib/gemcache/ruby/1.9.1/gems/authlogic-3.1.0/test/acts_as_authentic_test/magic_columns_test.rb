require 'test_helper'

module ActsAsAuthenticTest
  class MagicColumnsTest < ActiveSupport::TestCase
    def test_validates_numericality_of_login_count
      u = User.new
      u.login_count = -1
      assert !u.valid?
      assert u.errors[:login_count].size > 0
      
      u.login_count = 0
      assert !u.valid?
      assert u.errors[:login_count].size == 0
    end
    
    def test_validates_numericality_of_failed_login_count
      u = User.new
      u.failed_login_count = -1
      assert !u.valid?
      assert u.errors[:failed_login_count].size > 0
      
      u.failed_login_count = 0
      assert !u.valid?
      assert u.errors[:failed_login_count].size == 0
    end
  end
end