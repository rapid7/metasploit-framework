require 'em_test_helper'


class TestSASL < Test::Unit::TestCase

  # SASL authentication is usually done with UNIX-domain sockets, but
  # we'll use TCP so this test will work on Windows. As far as the
  # protocol handlers are concerned, there's no difference.

  TestUser,TestPsw = "someone", "password"

  class SaslServer < EM::Connection
    include EM::Protocols::SASLauth
    def validate usr, psw, sys, realm
      usr == TestUser and psw == TestPsw
    end
  end

  class SaslClient < EM::Connection
    include EM::Protocols::SASLauthclient
  end

  def setup
    @port = next_port
  end

  def test_sasl
    resp = nil
    EM.run {
      EM.start_server( "127.0.0.1", @port, SaslServer )

      c = EM.connect( "127.0.0.1", @port, SaslClient )
      d = c.validate?( TestUser, TestPsw )
      d.timeout 1
      d.callback {
        resp = true
        EM.stop
      }
      d.errback {
        resp = false
        EM.stop
      }
    }
    assert_equal( true, resp )
  end

end
