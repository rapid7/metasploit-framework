require 'em_test_helper'

class TestPure < Test::Unit::TestCase

  def setup
    @port = next_port
  end

  # These tests are intended to exercise problems that come up in the
  # pure-Ruby implementation. However, we DON'T constrain them such that
  # they only run in pure-Ruby. These tests need to work identically in
  # any implementation.

  #-------------------------------------

  # The EM reactor needs to run down open connections and release other resources
  # when it stops running. Make sure this happens even if user code throws a Ruby
  # exception.
  # If exception handling is incorrect, the second test will fail with a no-bind error
  # because the TCP server opened in the first test will not have been closed.

  def test_exception_handling_releases_resources
    exception = Class.new(StandardError)

    2.times do
      assert_raises(exception) do
        EM.run do
          EM.start_server "127.0.0.1", @port
          raise exception
        end
      end
    end
  end

  # Under some circumstances, the pure Ruby library would emit an Errno::ECONNREFUSED
  # exception on certain kinds of TCP connect-errors.
  # It's always been something of an open question whether EM should throw an exception
  # in these cases but the defined answer has always been to catch it the unbind method.
  # With a connect failure, the latter will always fire, but connection_completed will
  # never fire. So even though the point is arguable, it's incorrect for the pure Ruby
  # version to throw an exception.
  module TestConnrefused
    def unbind
      EM.stop
    end
    def connection_completed
      raise "should never get here"
    end
  end

  def test_connrefused
    assert_nothing_raised do
      EM.run {
        setup_timeout(2)
        EM.connect "127.0.0.1", @port, TestConnrefused
      }
    end
  end

  # Make sure connection_completed gets called as expected with TCP clients. This is the
  # opposite of test_connrefused.
  # If the test fails, it will hang because EM.stop never gets called.
  #
  module TestConnaccepted
    def connection_completed
      EM.stop
    end
  end
  def test_connaccepted
    assert_nothing_raised do
      EM.run {
        EM.start_server "127.0.0.1", @port
        EM.connect "127.0.0.1", @port, TestConnaccepted
        setup_timeout(1)
      }
    end
  end

  def test_reactor_running
    a = false
    EM.run {
      a = EM.reactor_running?
      EM.next_tick {EM.stop}
    }
    assert a
  end

  module TLSServer
    def post_init
      start_tls
    end

    def ssl_handshake_completed
      $server_handshake_completed = true
    end

    def receive_data(data)
      $server_received_data = data
      send_data(data)
    end
  end

  module TLSClient
    def post_init
      start_tls
    end

    def ssl_handshake_completed
      $client_handshake_completed = true
    end

    def connection_completed
      send_data('Hello World!')
    end

    def receive_data(data)
      $client_received_data = data
      close_connection
    end

    def unbind
      EM.stop_event_loop
    end
  end

  def test_start_tls
    $client_handshake_completed, $server_handshake_completed = false, false
    $client_received_data, $server_received_data = nil, nil
    EM.run do
      EM.start_server("127.0.0.1", 16789, TLSServer)
      EM.connect("127.0.0.1", 16789, TLSClient)
    end

    assert($client_handshake_completed)
    assert($server_handshake_completed)
    assert($client_received_data == "Hello World!")
    assert($server_received_data == "Hello World!")
  end
end
