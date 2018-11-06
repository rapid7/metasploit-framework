require 'em_test_helper'

if EM.kqueue?
  class TestProcessWatch < Test::Unit::TestCase
    module ParentProcessWatcher
      def process_forked
        $forked = true
      end
    end

    module ChildProcessWatcher
      def process_exited
        $exited = true
      end
      def unbind
        $unbind = true
        EM.stop
      end
    end

    def setup
      EM.kqueue = true
    end

    def teardown
      EM.kqueue = false
    end

    def test_events
      omit_if(rbx?)
      omit_if(jruby?)
      EM.run{
        # watch ourselves for a fork notification
        EM.watch_process(Process.pid, ParentProcessWatcher)
        $fork_pid = fork{ sleep }
        child = EM.watch_process($fork_pid, ChildProcessWatcher)
        $pid = child.pid

        EM.add_timer(0.2){
          Process.kill('TERM', $fork_pid)
        }
      }

      assert_equal($pid, $fork_pid)
      assert($forked)
      assert($exited)
      assert($unbind)
    end
  end
end
