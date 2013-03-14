
require 'em_test_helper'



class TestSpawn < Test::Unit::TestCase

  # Spawn a process that simply stops the reactor.
  # Assert that the notification runs after the block that calls it.
  #
  def test_stop
    x = nil
    EM.run {
      s = EM.spawn {EM.stop}
      s.notify
      x = true
    }
    assert x
  end


  # Pass a parameter to a spawned process.
  #
  def test_parms
    val = 5
    EM.run {
      s = EM.spawn {|v| val *= v; EM.stop}
      s.notify 3
    }
    assert_equal( 15, val )
  end

  # Pass multiple parameters to a spawned process.
  #
  def test_multiparms
    val = 5
    EM.run {
      s = EM.spawn {|v1,v2| val *= (v1 + v2); EM.stop}
      s.notify 3,4
    }
    assert_equal( 35, val )
  end


  # This test demonstrates that a notification does not happen immediately,
  # but rather is scheduled sometime after the current code path completes.
  #
  def test_race
    x = 0
    EM.run {
      s = EM.spawn {x *= 2; EM.stop}
      s.notify
      x = 2
    }
    assert_equal( 4, x)
  end


  # Spawn a process and notify it 25 times to run fibonacci
  # on a pair of global variables.
  #
  def test_fibonacci
    x = 1
    y = 1
    EM.run {
      s = EM.spawn {x,y = y,x+y}
      25.times {s.notify}

      t = EM.spawn {EM.stop}
      t.notify
    }
    assert_equal( 121393, x)
    assert_equal( 196418, y)
  end

  # This one spawns 25 distinct processes, and notifies each one once,
  # rather than notifying a single process 25 times.
  #
  def test_another_fibonacci
    x = 1
    y = 1
    EM.run {
      25.times {
      s = EM.spawn {x,y = y,x+y}
      s.notify
    }

    t = EM.spawn {EM.stop}
    t.notify
    }
    assert_equal( 121393, x)
    assert_equal( 196418, y)
  end


  # Make a chain of processes that notify each other in turn
  # with intermediate fibonacci results. The final process in
  # the chain stops the loop and returns the result.
  #
  def test_fibonacci_chain
    a,b = nil

    EM.run {
      nextpid = EM.spawn {|x,y|
        a,b = x,y
        EM.stop
      }

      25.times {
        n = nextpid
        nextpid = EM.spawn {|x,y| n.notify( y, x+y )}
      }

      nextpid.notify( 1, 1 )
    }

    assert_equal( 121393, a)
    assert_equal( 196418, b)
  end


  # EM#yield gives a spawed process to yield control to other processes
  # (in other words, to stop running), and to specify a different code block
  # that will run on its next notification.
  #
  def test_yield
    a = 0
    EM.run {
      n = EM.spawn {
        a += 10
        EM.yield {
          a += 20
          EM.yield {
            a += 30
            EM.stop
          }
        }
      }
      n.notify
      n.notify
      n.notify
    }
    assert_equal( 60, a )
  end

  # EM#yield_and_notify behaves like EM#yield, except that it also notifies the
  # yielding process. This may sound trivial, since the yield block will run very
  # shortly after with no action by the program, but this actually can be very useful,
  # because it causes the reactor core to execute once before the yielding process
  # gets control back. So it can be used to allow heavily-used network connections
  # to clear buffers, or allow other processes to process their notifications.
  #
  # Notice in this test code that only a simple notify is needed at the bottom
  # of the initial block. Even so, all of the yielded blocks will execute.
  #
  def test_yield_and_notify
    a = 0
    EM.run {
      n = EM.spawn {
        a += 10
        EM.yield_and_notify {
          a += 20
          EM.yield_and_notify {
            a += 30
            EM.stop
          }
        }
      }
      n.notify
    }
    assert_equal( 60, a )
  end

  # resume is an alias for notify.
  #
  def test_resume
    EM.run {
      n = EM.spawn {EM.stop}
      n.resume
    }
    assert true
  end

  # run is an idiomatic alias for notify.
  #
  def test_run
    EM.run {
      (EM.spawn {EM.stop}).run
    }
    assert true
  end


  # Clones the ping-pong example from the Erlang tutorial, in much less code.
  # Illustrates that a spawned block executes in the context of a SpawnableObject.
  # (Meaning, we can pass self as a parameter to another process that can then
  # notify us.)
  #
  def test_ping_pong
    n_pongs = 0
    EM.run {
      pong = EM.spawn {|x, ping|
        n_pongs += 1
        ping.notify( x-1 )
      }
      ping = EM.spawn {|x|
        if x > 0
          pong.notify x, self
        else
          EM.stop
        end
      }
      ping.notify 3
    }
    assert_equal( 3, n_pongs )
  end

  # Illustrates that you can call notify inside a notification, and it will cause
  # the currently-executing process to be re-notified. Of course, the new notification
  # won't run until sometime after the current one completes.
  #
  def test_self_notify
    n = 0
    EM.run {
      pid = EM.spawn {|x|
        if x > 0
          n += x
          notify( x-1 )
        else
          EM.stop
        end
      }
      pid.notify 3
    }
    assert_equal( 6, n )
  end


  # Illustrates that the block passed to #spawn executes in the context of a
  # SpawnedProcess object, NOT in the local context. This can often be deceptive.
  #
  class BlockScopeTest
    attr_reader :var
    def run
      # The following line correctly raises a NameError.
      # The problem is that the programmer expected the spawned block to
      # execute in the local context, but it doesn't.
      #
      # (EM.spawn { do_something }).notify ### NO! BAD!



      # The following line correctly passes self as a parameter to the
      # notified process.
      #
      (EM.spawn {|obj| obj.do_something }).notify(self)



      # Here's another way to do it. This works because "myself" is bound
      # in the local scope, unlike "self," so the spawned block sees it.
      #
      myself = self
      (EM.spawn { myself.do_something }).notify



      # And we end the loop.
      # This is a tangential point, but observe that #notify never blocks.
      # It merely appends a message to the internal queue of a spawned process
      # and returns. As it turns out, the reactor processes notifications for ALL
      # spawned processes in the order that #notify is called. So there is a
      # reasonable expectation that the process which stops the reactor will
      # execute after the previous ones in this method. HOWEVER, this is NOT
      # a documented behavior and is subject to change.
      #
      (EM.spawn {EM.stop}).notify
    end
    def do_something
      @var ||= 0
      @var += 100
    end
  end

  def test_block_scope
    bs = BlockScopeTest.new
    EM.run {
      bs.run
    }
    assert_equal( 200, bs.var )
  end

end
