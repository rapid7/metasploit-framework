require 'em_test_helper'
require 'socket'

class TestManyFDs < Test::Unit::TestCase
  def setup
    @port = next_port
  end

  def test_connection_class_cache
    mod = Module.new
    a = nil
    Process.setrlimit(Process::RLIMIT_NOFILE, 4096) rescue nil
    EM.run {
      EM.start_server '127.0.0.1', @port, mod
      1100.times do
        a = EM.connect '127.0.0.1', @port, mod
        assert_kind_of EM::Connection, a
      end
      EM.stop
    }
  end
end
