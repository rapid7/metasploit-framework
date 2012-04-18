$:.unshift "../lib"
require 'eventmachine'
require 'test/unit'

class TestInactivityTimeout < Test::Unit::TestCase

  def test_default
    $timeout = nil
    EM.run {
      c = EM.connect("127.0.0.1", 54321)
      $timeout = c.comm_inactivity_timeout
      EM.stop
    }

    assert_equal(0.0, $timeout)
  end

  def test_set_and_get
    $timeout = nil
    EM.run {
      c = EM.connect("127.0.0.1", 54321)
      c.comm_inactivity_timeout = 2.5
      $timeout = c.comm_inactivity_timeout
      EM.stop
    }

    assert_equal(2.5, $timeout)
  end

  module TimeoutHandler
    def unbind
      EM.stop
    end
  end

  def test_for_real
    EM.run {
      EM.heartbeat_interval = 0.1
      EM.start_server("127.0.0.1", 12345)
      EM.add_timer(0.2) {
        $start = Time.now
        c = EM.connect("127.0.0.1", 12345, TimeoutHandler)
        c.comm_inactivity_timeout = 2.5
      }
    }

    assert_in_delta(2.5, (Time.now - $start), 0.3)
  end

end
