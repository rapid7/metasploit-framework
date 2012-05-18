require 'test_helper'

module SessionTest
  module ExistenceTest
    class ClassMethodsTest < ActiveSupport::TestCase
      def test_create
        ben = users(:ben)
        assert UserSession.create(:login => "somelogin", :password => "badpw2").new_session?
        assert !UserSession.create(:login => ben.login, :password => "benrocks").new_session?
        assert_raise(Authlogic::Session::Existence::SessionInvalidError) { UserSession.create!(:login => ben.login, :password => "badpw") }
        assert !UserSession.create!(:login => ben.login, :password => "benrocks").new_session?
      end
    end
    
    class IsntaceMethodsTest < ActiveSupport::TestCase
      def test_new_session
        session = UserSession.new
        assert session.new_session?
      
        set_session_for(users(:ben))
        session = UserSession.find
        assert !session.new_session?
      end
    
      def test_save_with_nothing
        session = UserSession.new
        assert !session.save
        assert session.new_session?
      end
    
      def test_save_with_block
        ben = users(:ben)
        session = UserSession.new
        block_result = session.save do |result|
          assert !result
        end
        assert !block_result
        assert session.new_session?
      end
    
      def test_save_with_bang
        session = UserSession.new
        assert_raise(Authlogic::Session::Existence::SessionInvalidError) { session.save! }
      
        session.unauthorized_record = users(:ben)
        assert_nothing_raised { session.save! }
      end
    
      def test_destroy
        ben = users(:ben)
        session = UserSession.new
        assert !session.valid?
        assert !session.errors.empty?
        assert session.destroy
        assert session.errors.empty?
        session.unauthorized_record = ben
        assert session.save
        assert session.record
        assert session.destroy
        assert !session.record
      end
    end
  end
end