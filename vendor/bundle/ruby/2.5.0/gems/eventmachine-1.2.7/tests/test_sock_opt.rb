require 'em_test_helper'
require 'socket'

class TestSockOpt < Test::Unit::TestCase
  def setup
    assert(!EM.reactor_running?)
    @port = next_port
  end

  def teardown
    assert(!EM.reactor_running?)
  end

  def test_set_sock_opt
    omit_if(windows?)
    omit_if(!EM.respond_to?(:set_sock_opt))

    val = nil
    test_module = Module.new do
      define_method :post_init do
        val = set_sock_opt Socket::SOL_SOCKET, Socket::SO_BROADCAST, true
        EM.stop
      end
    end

    EM.run do
      EM.start_server '127.0.0.1', @port
      EM.connect '127.0.0.1', @port, test_module
    end

    assert_equal 0, val
  end

  def test_get_sock_opt
    omit_if(windows?)
    omit_if(!EM.respond_to?(:set_sock_opt))

    val = nil
    test_module = Module.new do
      define_method :connection_completed do
        val = get_sock_opt Socket::SOL_SOCKET, Socket::SO_ERROR
        EM.stop
      end
    end

    EM.run do
      EM.start_server '127.0.0.1', @port
      EM.connect '127.0.0.1', @port, test_module
    end

    assert_equal "\0\0\0\0", val
  end

end
