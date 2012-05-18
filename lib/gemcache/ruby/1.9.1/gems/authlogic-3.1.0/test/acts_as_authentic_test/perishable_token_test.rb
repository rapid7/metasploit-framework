require 'test_helper'

module ActsAsAuthenticTest
  class PerishableTokenTest < ActiveSupport::TestCase
    def test_perishable_token_valid_for_config
      assert_equal 10.minutes.to_i, User.perishable_token_valid_for
      assert_equal 10.minutes.to_i, Employee.perishable_token_valid_for
      
      User.perishable_token_valid_for = 1.hour
      assert_equal 1.hour.to_i, User.perishable_token_valid_for
      User.perishable_token_valid_for 10.minutes
      assert_equal 10.minutes.to_i, User.perishable_token_valid_for
    end
    
    def test_disable_perishable_token_maintenance_config
      assert !User.disable_perishable_token_maintenance
      assert !Employee.disable_perishable_token_maintenance
      
      User.disable_perishable_token_maintenance = true
      assert User.disable_perishable_token_maintenance
      User.disable_perishable_token_maintenance false
      assert !User.disable_perishable_token_maintenance
    end
    
    def test_validates_uniqueness_of_perishable_token
      u = User.new
      u.perishable_token = users(:ben).perishable_token
      assert !u.valid?
      assert u.errors[:perishable_token].size > 0
    end
    
    def test_before_save_reset_perishable_token
      ben = users(:ben)
      old_perishable_token = ben.perishable_token
      assert ben.save
      assert_not_equal old_perishable_token, ben.perishable_token
    end
    
    def test_reset_perishable_token
      ben = users(:ben)
      old_perishable_token = ben.perishable_token
      
      assert ben.reset_perishable_token
      assert_not_equal old_perishable_token, ben.perishable_token
      
      ben.reload
      assert_equal old_perishable_token, ben.perishable_token
      
      assert ben.reset_perishable_token!
      assert_not_equal old_perishable_token, ben.perishable_token
      
      ben.reload
      assert_not_equal old_perishable_token, ben.perishable_token
    end
    
    def test_find_using_perishable_token
      ben = users(:ben)
      assert_equal ben, User.find_using_perishable_token(ben.perishable_token)
    end
    
    def test_find_using_perishable_token_when_perished
      ben = users(:ben)
      ActiveRecord::Base.connection.execute("UPDATE users set updated_at = '#{1.week.ago.to_s(:db)}' where id = #{ben.id}")
      assert_nil User.find_using_perishable_token(ben.perishable_token)
    end
    
    def test_find_using_perishable_token_when_perished
      User.perishable_token_valid_for = 1.minute
      ben = users(:ben)
      ActiveRecord::Base.connection.execute("UPDATE users set updated_at = '#{2.minutes.ago.to_s(:db)}' where id = #{ben.id}")
      assert_nil User.find_using_perishable_token(ben.perishable_token)
      User.perishable_token_valid_for = 10.minutes
    end
    
    def test_find_using_perishable_token_when_passing_threshold
      User.perishable_token_valid_for = 1.minute
      ben = users(:ben)
      ActiveRecord::Base.connection.execute("UPDATE users set updated_at = '#{10.minutes.ago.to_s(:db)}' where id = #{ben.id}")
      assert_nil User.find_using_perishable_token(ben.perishable_token, 5.minutes)
      assert_equal ben, User.find_using_perishable_token(ben.perishable_token, 20.minutes)
      User.perishable_token_valid_for = 10.minutes
    end

    def test_find_perishable_token_with_bang
      assert_raises ActiveRecord::RecordNotFound do
        User.find_using_perishable_token!('some_bad_value')
      end
    end
  end
end
