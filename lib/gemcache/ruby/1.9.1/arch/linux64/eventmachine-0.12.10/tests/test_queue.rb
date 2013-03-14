$:.unshift "../lib"
require 'eventmachine'
require 'test/unit'

class TestEventMachineQueue < Test::Unit::TestCase
  def test_queue_push
    s = 0
    EM.run do
      q = EM::Queue.new
      q.push(1)
      EM.next_tick { s = q.size; EM.stop }
    end
    assert_equal 1, s
  end

  def test_queue_pop
    x,y,z = nil
    EM.run do
      q = EM::Queue.new
      q.push(1,2,3)
      q.pop { |v| x = v }
      q.pop { |v| y = v }
      q.pop { |v| z = v; EM.stop }
    end
    assert_equal 1, x
    assert_equal 2, y
    assert_equal 3, z
  end

  def test_queue_reactor_thread
    q = EM::Queue.new

    Thread.new { q.push(1,2,3) }.join
    assert q.empty?
    EM.run { EM.next_tick { EM.stop } }
    assert_equal 3, q.size

    x = nil
    Thread.new { q.pop { |v| x = v } }.join
    assert_equal nil, x
    EM.run { EM.next_tick { EM.stop } }
    assert_equal 1, x
  end
end
