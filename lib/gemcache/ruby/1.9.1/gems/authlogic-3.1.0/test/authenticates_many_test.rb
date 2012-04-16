require 'test_helper'

class AuthenticatesManyTest < ActiveSupport::TestCase
  def test_scoping
    zack = users(:zack)
    ben = users(:ben)
    binary_logic = companies(:binary_logic)
    set_session_for(zack)
    
    assert !binary_logic.user_sessions.find
    
    set_session_for(ben)
    
    assert binary_logic.user_sessions.find
  end
end