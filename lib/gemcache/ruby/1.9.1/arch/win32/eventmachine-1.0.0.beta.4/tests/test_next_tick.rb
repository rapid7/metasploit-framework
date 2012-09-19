require 'em_test_helper'

class TestNextTick < Test::Unit::TestCase

  def test_tick_arg
    pr = proc {EM.stop}
    EM.run {
      EM.next_tick pr
    }
    assert true
  end

  def test_tick_block
    EM.run {
      EM.next_tick {EM.stop}
    }
    assert true
  end

  # This illustrates the solution to a long-standing problem.
  # It's now possible to correctly nest calls to EM#run.
  # See the source code commentary for EM#run for more info.
  #
  def test_run_run
    EM.run {
      EM.run {
        EM.next_tick {EM.stop}
      }
    }
  end

  def test_pre_run_queue
    x = false
    EM.next_tick { EM.stop; x = true }
    EM.run { EM.add_timer(0.01) { EM.stop } }
    assert x
  end

  def test_cleanup_after_stop
    x = true
    EM.run{
      EM.next_tick{
        EM.stop
        EM.next_tick{ x=false }
      }
    }
    EM.run{
      EM.next_tick{ EM.stop }
    }
    assert x
  end

  # We now support an additional parameter for EM#run.
  # You can pass two procs to EM#run now. The first is executed as the normal
  # run block. The second (if given) is scheduled for execution after the
  # reactor loop completes.
  # The reason for supporting this is subtle. There has always been an expectation
  # that EM#run doesn't return until after the reactor loop ends. But now it's
  # possible to nest calls to EM#run, which means that a nested call WILL
  # RETURN. In order to write code that will run correctly either way, it's
  # recommended to put any code which must execute after the reactor completes
  # in the second parameter.
  #
  def test_run_run_2
    a = proc {EM.stop}
    b = proc {assert true}
    EM.run a, b
  end


  # This illustrates that EM#run returns when it's called nested.
  # This isn't a feature, rather it's something to be wary of when writing code
  # that must run correctly even if EM#run is called while a reactor is already
  # running.
  def test_run_run_3
    a = []
    EM.run {
      EM.run proc {EM.stop}, proc {a << 2}
      a << 1
    }
    assert_equal( [1,2], a )
  end


  def test_schedule_on_reactor_thread
    x = false
    EM.run do
      EM.schedule { x = true }
      EM.stop
    end
    assert x
  end

  def test_schedule_from_thread
    x = false
    EM.run do
      Thread.new { EM.schedule { x = true } }.join
      assert !x
      EM.next_tick { EM.stop }
    end
    assert x
  end

end
