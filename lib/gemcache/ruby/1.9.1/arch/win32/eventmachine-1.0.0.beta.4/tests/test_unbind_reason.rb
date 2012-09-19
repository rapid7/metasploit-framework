require 'em_test_helper'
require 'socket'

class TestUnbindReason < Test::Unit::TestCase

  class StubConnection < EM::Connection
    attr_reader :error
    def unbind(reason = nil)
      @error = reason
      EM.stop
    end
  end

  def test_connect_timeout
    error = nil
    EM.run {
      conn = EM.connect 'google.com', 81, Module.new{ |m|
        m.send(:define_method, :unbind) do |reason|
          error = reason
          EM.stop
        end
      }
      conn.pending_connect_timeout = 0.1
    }
    assert_equal Errno::ETIMEDOUT, error
  end

  def test_connect_refused
    error = nil
    EM.run {
      EM.connect '127.0.0.1', 12388, Module.new{ |m|
        m.send(:define_method, :unbind) do |reason|
          error = reason
          EM.stop
        end
      }
    }
    assert_equal Errno::ECONNREFUSED, error
  end

  def test_optional_argument
    conn = nil
    EM.run {
      conn = EM.connect '127.0.0.1', 12388, StubConnection
    }
    assert_equal Errno::ECONNREFUSED, conn.error
  end
end
