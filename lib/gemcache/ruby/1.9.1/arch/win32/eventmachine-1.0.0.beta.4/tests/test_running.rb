require 'em_test_helper'

class TestRunning < Test::Unit::TestCase
  def test_running
    assert_equal( false, EM::reactor_running? )
    r = false
    EM.run {
      r = EM::reactor_running?
      EM.stop
    }
    assert_equal( true, r )
  end
end

