require_relative "test_helper"
require 'timecop'

class TestTimecopWithoutDate < Minitest::Test

  def setup
    Object.send(:remove_const, :Date) if Object.const_defined?(:Date)
    Object.send(:remove_const, :DateTime) if Object.const_defined?(:DateTime)
  end

  # just in case...let's really make sure that Timecop is disabled between tests...
  def teardown
    Timecop.return
  end

  def test_freeze_changes_and_resets_time
    # depending on how we're invoked (individually or via the rake test suite)
    assert !Time.respond_to?(:zone) || Time.zone.nil?

    t = Time.local(2008, 10, 10, 10, 10, 10)
    assert t != Time.now
    Timecop.freeze(2008, 10, 10, 10, 10, 10) do
      assert_equal t, Time.now
    end
    assert t != Time.now
  end

  def test_recursive_freeze
    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.freeze(2008, 10, 10, 10, 10, 10) do
      assert_equal t, Time.now
      t2 = Time.local(2008, 9, 9, 9, 9, 9)
      Timecop.freeze(2008, 9, 9, 9, 9, 9) do
        assert_equal t2, Time.now
      end
      assert_equal t, Time.now
    end
    assert_nil Time.send(:mock_time)
  end

  def test_exception_thrown_in_freeze_block_properly_resets_time
    t = Time.local(2008, 10, 10, 10, 10, 10)
    begin
      Timecop.freeze(t) do
        assert_equal t, Time.now
        raise "blah exception"
      end
    rescue
      assert t != Time.now
      assert_nil Time.send(:mock_time)
    end
  end

  def test_freeze_freezes_time
    t = Time.local(2008, 10, 10, 10, 10, 10)
    now = Time.now
    Timecop.freeze(t) do
      sleep(0.25)
      assert Time.now < now, "If we had failed to freeze, time would have proceeded, which is what appears to have happened."
      new_t = Time.now
      assert_equal t, new_t, "Failed to change move time." # 2 seconds
      assert_equal new_t, Time.now
    end
  end

  def test_travel_keeps_time_moving
    t = Time.local(2008, 10, 10, 10, 10, 10)
    now = Time.now
    Timecop.travel(t) do
      new_now = Time.now
      assert_times_effectively_equal new_now, t, 1, "Looks like we failed to actually travel time" # 0.1 seconds
      sleep(0.25)
      assert_times_effectively_not_equal new_now, Time.now, 0.24, "Looks like time is not moving"
    end
  end

  def test_recursive_travel_maintains_each_context
    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.travel(2008, 10, 10, 10, 10, 10) do
      assert((t - Time.now).abs < 50, "Failed to travel time.")
      t2 = Time.local(2008, 9, 9, 9, 9, 9)
      Timecop.travel(2008, 9, 9, 9, 9, 9) do
        assert_times_effectively_equal(t2, Time.now, 1, "Failed to travel time.")
        assert_times_effectively_not_equal(t, Time.now, 1000, "Failed to travel time.")
      end
      assert_times_effectively_equal(t, Time.now, 2, "Failed to restore previously-traveled time.")
    end
    assert_nil Time.send(:mock_time)
  end

  def test_recursive_travel_then_freeze
    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.travel(2008, 10, 10, 10, 10, 10) do
      assert((t - Time.now).abs < 50, "Failed to travel time.")
      t2 = Time.local(2008, 9, 9, 9, 9, 9)
      Timecop.freeze(2008, 9, 9, 9, 9, 9) do
        assert_equal t2, Time.now
      end
      assert_times_effectively_equal(t, Time.now, 2, "Failed to restore previously-traveled time.")
    end
    assert_nil Time.send(:mock_time)
  end

  def test_recursive_freeze_then_travel
    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.freeze(t) do
      assert_equal t, Time.now
      t2 = Time.local(2008, 9, 9, 9, 9, 9)
      Timecop.travel(t2) do
        assert_times_effectively_equal(t2, Time.now, 1, "Failed to travel time.")
        assert_times_effectively_not_equal(t, Time.now, 1000, "Failed to travel time.")
      end
      assert_equal t, Time.now
    end
    assert_nil Time.send(:mock_time)
  end

end
