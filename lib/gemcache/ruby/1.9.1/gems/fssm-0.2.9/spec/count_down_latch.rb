#!/usr/bin/env ruby
# coding: utf-8

require 'thread'

class CountDownLatch
  attr_reader :count

  def initialize(to)
    @count = to.to_i
    raise ArgumentError, "cannot count down from negative integer" unless @count >= 0
    @lock      = Mutex.new
    @condition = ConditionVariable.new
  end

  def count_down
    @lock.synchronize do
      @count -= 1 if @count > 0
      @condition.broadcast if @count == 0
    end
  end

  def wait
    @lock.synchronize do
      @condition.wait(@lock) while @count > 0
    end
  end
end

if $0 == __FILE__
  require 'test/unit'

  class CountDownLatchTest < Test::Unit::TestCase
    def test_requires_positive_count
      assert_raise(ArgumentError) { CountDownLatch.new(-1) }
    end

    def test_basic_latch_usage
      latch = CountDownLatch.new(1)
      name  = "foo"
      Thread.new do
        name = "bar"
        latch.count_down
      end
      latch.wait
      assert_equal(0, latch.count)
      assert_equal("bar", name)
    end

    def test_basic_latch_usage_inverted
      latch = CountDownLatch.new(1)
      name  = "foo"
      Thread.new do
        latch.wait
        assert_equal(0, latch.count)
        assert_equal("bar", name)
      end
      name = "bar"
      latch.count_down
    end

    def test_count_down_from_zero_skips_wait
      latch = CountDownLatch.new(0)
      latch.wait
      assert_equal(0, latch.count)
    end

    def test_count_down_twice_with_thread
      latch = CountDownLatch.new(2)
      name  = "foo"
      Thread.new do
        latch.count_down
        name = "bar"
        latch.count_down
      end
      latch.wait
      assert_equal(0, latch.count)
      assert_equal("bar", name)
    end

    def test_count_down_twice_with_two_parallel_threads
      latch = CountDownLatch.new(2)
      name  = "foo"
      Thread.new { latch.count_down }
      Thread.new do
        name = "bar"
        latch.count_down
      end
      latch.wait
      assert_equal(0, latch.count)
      assert_equal("bar", name)
    end

    def test_count_down_twice_with_two_chained_threads
      latch = CountDownLatch.new(2)
      name  = "foo"
      Thread.new do
        latch.count_down
        Thread.new do
          name = "bar"
          latch.count_down
        end
      end
      latch.wait
      assert_equal(0, latch.count)
      assert_equal("bar", name)
    end

    def test_count_down_with_multiple_waiters
      proceed_latch = CountDownLatch.new(2)
      check_latch   = CountDownLatch.new(2)
      results       = {}
      Thread.new do
        proceed_latch.wait
        results[:first] = 1
        check_latch.count_down
      end
      Thread.new do
        proceed_latch.wait
        results[:second] = 2
        check_latch.count_down
      end
      assert_equal({}, results)
      proceed_latch.count_down
      proceed_latch.count_down
      check_latch.wait
      assert_equal(0, proceed_latch.count)
      assert_equal(0, check_latch.count)
      assert_equal({:first => 1, :second => 2}, results)
    end

    def test_interleaved_latches
      change_1_latch = CountDownLatch.new(1)
      check_latch    = CountDownLatch.new(1)
      change_2_latch = CountDownLatch.new(1)
      name           = "foo"
      Thread.new do
        name = "bar"
        change_1_latch.count_down
        check_latch.wait
        name = "man"
        change_2_latch.count_down
      end
      change_1_latch.wait
      assert_equal("bar", name)
      check_latch.count_down
      change_2_latch.wait
      assert_equal("man", name)
    end
  end
end
