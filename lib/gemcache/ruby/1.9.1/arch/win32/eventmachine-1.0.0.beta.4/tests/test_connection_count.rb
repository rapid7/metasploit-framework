require 'em_test_helper'

class TestConnectionCount < Test::Unit::TestCase
  def test_idle_connection_count
    EM.run {
      $count = EM.connection_count
      EM.stop_event_loop
    }

    assert_equal(0, $count)
  end

  module Client
    def connection_completed
      $client_conns += 1
      EM.stop if $client_conns == 3
    end
  end

  def test_with_some_connections
    EM.run {
      $client_conns = 0
      $initial_conns = EM.connection_count
      EM.start_server("127.0.0.1", 9999)
      $server_conns = EM.connection_count
      3.times { EM.connect("127.0.0.1", 9999, Client) }
    }

    assert_equal(0, $initial_conns)
    assert_equal(1, $server_conns)
    assert_equal(4, $client_conns + $server_conns)
  end
end