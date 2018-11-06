require 'em_test_helper'

class TestFork < Test::Unit::TestCase

  def test_fork_safe
    omit_if(jruby?)
    omit_if(windows?)

    fork_pid = nil
    read, write = IO.pipe
    EM.run do
      fork_pid = fork do
        write.puts "forked"
        EM.run do
          EM.next_tick do
            write.puts "EM ran"
            EM.stop
          end
        end
      end
      EM.stop
    end

    sleep 0.1
    begin
      Timeout::timeout 1 do
        assert_equal "forked\n", read.readline
        assert_equal "EM ran\n", read.readline
      end
    rescue Timeout::Error
      Process.kill 'TERM', fork_pid
      flunk "Timeout waiting for next_tick in new fork reactor"
    end
  ensure
    read.close rescue nil
    write.close rescue nil
  end

  def test_fork_reactor
    omit_if(jruby?)
    omit_if(windows?)

    fork_pid = nil
    read, write = IO.pipe
    EM.run do
      EM.defer do
        write.puts Process.pid
        EM.defer do
          EM.stop
        end
      end
      fork_pid = EM.fork_reactor do
        EM.defer do
          write.puts Process.pid
          EM.stop
        end
      end
    end

    sleep 0.1
    begin
      Timeout::timeout 1 do
        assert_equal Process.pid.to_s, read.readline.chomp
        assert_equal fork_pid.to_s, read.readline.chomp
      end
    rescue Timeout::Error
      Process.kill 'TERM', fork_pid
      flunk "Timeout waiting for deferred block in fork_reactor"
    end
  ensure
    read.close rescue nil
    write.close rescue nil
  end

end
