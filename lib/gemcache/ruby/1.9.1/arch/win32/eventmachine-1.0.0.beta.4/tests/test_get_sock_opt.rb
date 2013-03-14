require 'em_test_helper'
require 'socket'

class TestGetSockOpt < Test::Unit::TestCase

  if EM.respond_to? :get_sock_opt
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
  else
    warn "EM.get_sock_opt not implemented, skipping tests in #{__FILE__}"

    # Because some rubies will complain if a TestCase class has no tests
    def test_em_get_sock_opt_unsupported
      assert true
    end
  end
end
