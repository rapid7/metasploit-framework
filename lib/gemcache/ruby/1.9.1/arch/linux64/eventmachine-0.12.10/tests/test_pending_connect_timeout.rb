$:.unshift "../lib"
require 'eventmachine'
require 'test/unit'

class TestPendingConnectTimeout < Test::Unit::TestCase

  def test_default
    $timeout = nil
    EM.run {
      c = EM.connect("127.0.0.1", 54321)
      $timeout = c.pending_connect_timeout
      EM.stop
    }

    assert_equal(20.0, $timeout)
  end

  def test_set_and_get
    $timeout = nil
    EM.run {
      c = EM.connect("1.2.3.4", 54321)
      c.pending_connect_timeout = 2.5
      $timeout = c.pending_connect_timeout
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
    $timeout = nil
    EM.run {
      EM.heartbeat_interval = 0.1
      $start = Time.now
      c = EM.connect("1.2.3.4", 54321, TimeoutHandler)
      c.pending_connect_timeout = 5
    }

    assert_in_delta(5, (Time.now - $start), 0.3)
  end

end
