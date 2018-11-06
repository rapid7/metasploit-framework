require 'em_test_helper'

class TestEMQueue < Test::Unit::TestCase
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

  def test_num_waiting
    q = EM::Queue.new
    many = 3
    many.times { q.pop {} }
    EM.run { EM.next_tick { EM.stop } }
    assert_equal many, q.num_waiting
  end

  def test_big_queue
    EM.run do
      q = EM::Queue.new
      2000.times do |i|
        q.push(*0..1000)
        q.pop { |v| assert_equal v, i % 1001 }
      end
      q.pop do
        assert_equal 1_999_999, q.size
        EM.stop
      end
    end
  end
end
