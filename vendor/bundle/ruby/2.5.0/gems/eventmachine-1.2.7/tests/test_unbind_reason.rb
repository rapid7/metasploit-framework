require 'em_test_helper'

class TestUnbindReason < Test::Unit::TestCase

  class StubConnection < EM::Connection
    attr_reader :error
    def unbind(reason = nil)
      @error = reason
      EM.stop
    end
  end

  # RFC 5737 Address Blocks Reserved for Documentation
  def test_connect_timeout
    conn = nil
    EM.run do
      conn = EM.connect '192.0.2.0', 80, StubConnection
      conn.pending_connect_timeout = 1
    end
    assert_equal Errno::ETIMEDOUT, conn.error
  end

  def test_connect_refused
    pend('FIXME: this test is broken on Windows') if windows?
    conn = nil
    EM.run do
      conn = EM.connect '127.0.0.1', 12388, StubConnection
    end
    assert_equal Errno::ECONNREFUSED, conn.error
  end

  def test_optional_argument
    pend('FIXME: this test is broken on Windows') if windows?
    conn = nil
    EM.run do
      conn = EM.connect '127.0.0.1', 12388, StubConnection
    end
    assert_equal Errno::ECONNREFUSED, conn.error
  end
end
