require "test/unit"
require 'em_test_helper'

class TestEmTickLoop < Test::Unit::TestCase
  def test_em_tick_loop
    i = 0
    EM.tick_loop { i += 1; EM.stop if i == 10 }
    EM.run { EM.add_timer(1) { EM.stop } }
    assert_equal i, 10
  end
  
  def test_tick_loop_on_stop
    t = nil
    tick_loop = EM.tick_loop { :stop }
    tick_loop.on_stop { t = true }
    EM.run { EM.next_tick { EM.stop } }
    assert t
  end
  
  def test_start_twice
    i = 0
    s = 0
    tick_loop = EM.tick_loop { i += 1; :stop }
    tick_loop.on_stop { s += 1; EM.stop }
    EM.run { EM.next_tick { EM.stop } }
    assert_equal 1, i
    assert_equal 1, s
    tick_loop.start
    EM.run { EM.next_tick { EM.stop } }
    assert_equal 2, i
    assert_equal 1, s # stop callbacks are only called once
  end
  
  def test_stop
    i, s = 0, 0
    tick_loop = EM.tick_loop { i += 1 }
    tick_loop.on_stop { s += 1 }
    EM.run { EM.next_tick { tick_loop.stop; EM.next_tick { EM.stop } } }
    assert tick_loop.stopped?
    assert_equal 1, i
    assert_equal 1, s
  end
  
  def test_immediate_stops
    s = 0
    tick_loop = EM::TickLoop.new { }
    tick_loop.on_stop { s += 1 }
    tick_loop.on_stop { s += 1 }
    assert_equal 2, s
  end
  
  def test_stopped
    tick_loop = EM::TickLoop.new { }
    assert tick_loop.stopped?
    tick_loop.start
    assert !tick_loop.stopped?
  end
    
end