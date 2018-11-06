require 'em_test_helper'

class TestConnectionCount < Test::Unit::TestCase
  def teardown
    EM.epoll = false
    EM.kqueue = false
  end

  def test_idle_connection_count
    count = nil
    EM.run {
      count = EM.connection_count
      EM.stop_event_loop
    }
    assert_equal(0, count)
  end

  # Run this again with epoll enabled (if available)
  def test_idle_connection_count_epoll
    EM.epoll if EM.epoll?

    count = nil
    EM.run {
      count = EM.connection_count
      EM.stop_event_loop
    }
    assert_equal(0, count)
  end

  # Run this again with kqueue enabled (if available)
  def test_idle_connection_count_kqueue
    EM.kqueue if EM.kqueue?

    count = nil
    EM.run {
      count = EM.connection_count
      EM.stop_event_loop
    }
    assert_equal(0, count)
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

  module DoubleCloseClient
    def unbind
      close_connection
      $num_close_scheduled_1 = EM.num_close_scheduled
      EM.next_tick do
        $num_close_scheduled_2 = EM.num_close_scheduled
        EM.stop
      end
    end
  end

  def test_num_close_scheduled
    omit_if(jruby?)
    EM.run {
      assert_equal(0, EM.num_close_scheduled)
      EM.connect("127.0.0.1", 9999, DoubleCloseClient) # nothing listening on 9999
    }
    assert_equal(1, $num_close_scheduled_1)
    assert_equal(0, $num_close_scheduled_2)
  end
end
