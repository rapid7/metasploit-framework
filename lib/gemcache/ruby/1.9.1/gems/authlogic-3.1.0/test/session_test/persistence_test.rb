require 'test_helper'

module SessionTest
  class PersistenceTest < ActiveSupport::TestCase
    def test_find
      ben = users(:ben)
      assert !UserSession.find
      http_basic_auth_for(ben) { assert UserSession.find }
      set_cookie_for(ben)
      assert UserSession.find
      unset_cookie
      set_session_for(ben)
      session = UserSession.find
      assert session
    end
    
    def test_persisting
      # tested thoroughly in test_find
    end
  end
end