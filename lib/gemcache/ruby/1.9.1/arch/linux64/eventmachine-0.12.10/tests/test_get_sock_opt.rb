$:.unshift File.expand_path(File.dirname(__FILE__) + "/../lib")
require 'eventmachine'
require 'socket'
require 'test/unit'

class TestGetSockOpt < Test::Unit::TestCase

  def setup
    assert(!EM.reactor_running?)
  end

  def teardown
    assert(!EM.reactor_running?)
  end

  #-------------------------------------

  def test_get_sock_opt
    test = self
    EM.run do
      EM.connect 'google.com', 80, Module.new {
        define_method :connection_completed do
          val = get_sock_opt Socket::SOL_SOCKET, Socket::SO_ERROR
          test.assert_equal "\0\0\0\0", val
          EM.stop
        end
      }
    end
  end
end
