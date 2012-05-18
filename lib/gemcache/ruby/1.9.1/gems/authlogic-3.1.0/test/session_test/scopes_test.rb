require 'test_helper'

module SessionTest
  class ScopesTest < ActiveSupport::TestCase
    def test_scope_method
      assert_nil Authlogic::Session::Base.scope

      thread1 = Thread.new do
        scope = {:id => :scope1}
        Authlogic::Session::Base.send(:scope=, scope)
        assert_equal scope, Authlogic::Session::Base.scope
      end
      thread1.join

      assert_nil Authlogic::Session::Base.scope

      thread2 = Thread.new do
        scope = {:id => :scope2}
        Authlogic::Session::Base.send(:scope=, scope)
        assert_equal scope, Authlogic::Session::Base.scope
      end
      thread2.join

      assert_nil Authlogic::Session::Base.scope
    end

    def test_with_scope_method
      assert_raise(ArgumentError) { UserSession.with_scope }

      UserSession.with_scope(:find_options => {:conditions => "awesome = 1"}, :id => "some_id") do
        assert_equal({:find_options => {:conditions => "awesome = 1"}, :id => "some_id"}, UserSession.scope)
      end

      assert_nil UserSession.scope
    end

    def test_initialize
      UserSession.with_scope(:find_options => {:conditions => "awesome = 1"}, :id => "some_id") do
        session = UserSession.new
        assert_equal({:find_options => {:conditions => "awesome = 1"}, :id => "some_id"}, session.scope)
        session.id = :another_id
        assert_equal "another_id_some_id_test", session.send(:build_key, "test")
      end
    end

    def test_search_for_record_with_scopes
      binary_logic = companies(:binary_logic)
      ben = users(:ben)
      zack = users(:zack)

      session = UserSession.new
      assert_equal zack, session.send(:search_for_record, "find_by_login", zack.login)

      session.scope = {:find_options => {:conditions => ["company_id = ?", binary_logic.id]}}
      assert_nil session.send(:search_for_record, "find_by_login", zack.login)

      assert_equal ben, session.send(:search_for_record, "find_by_login", ben.login)
    end
  end
end