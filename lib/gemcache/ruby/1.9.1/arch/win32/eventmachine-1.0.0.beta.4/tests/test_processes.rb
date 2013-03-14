require 'em_test_helper'

class TestProcesses < Test::Unit::TestCase

  if !windows? && !jruby?

    # EM::DeferrableChildProcess is a sugaring of a common use-case
    # involving EM::popen.
    # Call the #open method on EM::DeferrableChildProcess, passing
    # a command-string. #open immediately returns an EM::Deferrable
    # object. It also schedules the forking of a child process, which
    # will execute the command passed to #open.
    # When the forked child terminates, the Deferrable will be signalled
    # and execute its callbacks, passing the data that the child process
    # wrote to stdout.
    #
    def test_deferrable_child_process
      ls = ""
      EM.run {
        d = EM::DeferrableChildProcess.open( "ls -ltr" )
        d.callback {|data_from_child|
          ls = data_from_child
          EM.stop
        }
      }
      assert( ls.length > 0)
    end

    def setup
      $out = nil
      $status = nil
    end

    def test_em_system
      EM.run{
        EM.system('ls'){ |out,status| $out, $status = out, status; EM.stop }
      }

      assert( $out.length > 0 )
      assert_equal($status.exitstatus, 0)
      assert_equal($status.class, Process::Status)
    end

    def test_em_system_pid
      $pids = []

      EM.run{
        $pids << EM.system('echo hi', proc{ |out,status|$pids << status.pid; EM.stop })
      }

      assert_equal $pids[0], $pids[1]
    end

    def test_em_system_with_proc
      EM.run{
        EM.system('ls', proc{ |out,status| $out, $status = out, status; EM.stop })
      }

      assert( $out.length > 0 )
      assert_equal($status.exitstatus, 0)
      assert_equal($status.class, Process::Status)
    end

    def test_em_system_with_two_procs
      EM.run{
        EM.system('sh', proc{ |process|
          process.send_data("echo hello\n")
          process.send_data("exit\n")
        }, proc{ |out,status|
          $out = out
          $status = status
          EM.stop
        })
      }

      assert_equal("hello\n", $out)
    end

    def test_em_system_cmd_arguments
      EM.run{
        EM.system('echo', '1', '2', 'version', proc{ |process|
        }, proc{ |out,status|
          $out = out
          $status = status
          EM.stop
        })
      }

      assert_match(/1 2 version/i, $out)
    end

    def test_em_system_spaced_arguments
      EM.run{
        EM.system('ruby', '-e', 'puts "hello"', proc{ |out,status|
          $out = out
          EM.stop
        })
      }

      assert_equal("hello\n", $out)
    end

    def test_em_popen_pause_resume
      c_rx = 0

      test_client = Module.new do
        define_method :receive_data do |data|
          c_rx += 1
          pause
          EM.add_timer(0.5) { EM.stop }
        end
      end

      EM.run{
        EM.popen('cat /dev/random', test_client)
      }

      assert_equal 1, c_rx
    end
  else
    warn "EM.popen not implemented, skipping tests in #{__FILE__}"

    # Because some rubies will complain if a TestCase class has no tests
    def test_em_popen_unsupported
      assert true
    end
  end
end
