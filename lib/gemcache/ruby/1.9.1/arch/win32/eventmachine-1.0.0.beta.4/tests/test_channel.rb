require 'em_test_helper'

class TestEMChannel < Test::Unit::TestCase
  def test_channel_subscribe
    s = 0
    EM.run do
      c = EM::Channel.new
      c.subscribe { |v| s = v; EM.stop }
      c << 1
    end
    assert_equal 1, s
  end

  def test_channel_unsubscribe
    s = 0
    EM.run do
      c = EM::Channel.new
      subscription = c.subscribe { |v| s = v }
      c.unsubscribe(subscription)
      c << 1
      EM.next_tick { EM.stop }
    end
    assert_not_equal 1, s
  end

  def test_channel_pop
    s = 0
    EM.run do
      c = EM::Channel.new
      c.pop{ |v| s = v }
      c.push(1,2,3)
      c << 4
      c << 5
      EM.next_tick { EM.stop }
    end
    assert_equal 1, s
  end

  def test_channel_reactor_thread_push
    out = []
    c = EM::Channel.new
    c.subscribe { |v| out << v }
    Thread.new { c.push(1,2,3) }.join
    assert out.empty?

    EM.run { EM.next_tick { EM.stop } }

    assert_equal [1,2,3], out
  end

  def test_channel_reactor_thread_callback
    out = []
    c = EM::Channel.new
    Thread.new { c.subscribe { |v| out << v } }.join
    c.push(1,2,3)
    assert out.empty?

    EM.run { EM.next_tick { EM.stop } }

    assert_equal [1,2,3], out
  end
end