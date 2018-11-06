require_relative "test_helper"
require 'timecop'

class TestTimecop < Minitest::Test
  def teardown
    Timecop.return
  end

  def test_freeze_changes_and_resets_time
    outer_freeze_time = Time.local(2001, 01, 01)
    inner_freeze_block = Time.local(2002, 02, 02)
    inner_freeze_one = Time.local(2003, 03, 03)
    inner_freeze_two = Time.local(2004, 04, 04)

    Timecop.freeze(outer_freeze_time) do
      assert_times_effectively_equal outer_freeze_time, Time.now
      Timecop.freeze(inner_freeze_block) do
        assert_times_effectively_equal inner_freeze_block, Time.now
        Timecop.freeze(inner_freeze_one)
        assert_times_effectively_equal inner_freeze_one, Time.now
        Timecop.freeze(inner_freeze_two)
        assert_times_effectively_equal inner_freeze_two, Time.now
      end
      assert_times_effectively_equal outer_freeze_time, Time.now
    end
  end

  def test_freeze_yields_mocked_time
    Timecop.freeze(2008, 10, 10, 10, 10, 10) do |frozen_time|
      assert_equal frozen_time, Time.now
    end
  end

  def test_freeze_then_return_unsets_mock_time
    Timecop.freeze(1)
    Timecop.return
    assert_nil Time.send(:mock_time)
  end

  def test_travel_then_return_unsets_mock_time
    Timecop.travel(1)
    Timecop.return
    assert_nil Time.send(:mock_time)
  end

  def test_freeze_with_block_unsets_mock_time
    assert_nil Time.send(:mock_time), "test is invalid"
    Timecop.freeze(1) do; end
    assert_nil Time.send(:mock_time)
  end

  def test_travel_with_block_unsets_mock_time
    assert_nil Time.send(:mock_time), "test is invalid"
    Timecop.travel(1) do; end
    assert_nil Time.send(:mock_time)
  end

  def test_travel_does_not_reduce_precision_of_datetime
    # requires to_r on Float (>= 1.9)
    if Float.method_defined?(:to_r)
      Timecop.travel(Time.new(2014, 1, 1, 0, 0, 0))
      assert DateTime.now != DateTime.now

      Timecop.travel(Time.new(2014, 1, 1, 0, 0, 59))
      assert DateTime.now != DateTime.now
    end
  end

  def test_freeze_in_time_subclass_returns_mocked_subclass
    t = Time.local(2008, 10, 10, 10, 10, 10)
    custom_timeklass = Class.new(Time) do
      def custom_format_method() strftime('%F') end
    end

    Timecop.freeze(2008, 10, 10, 10, 10, 10) do
      assert custom_timeklass.now.is_a? custom_timeklass
      assert Time.now.eql? custom_timeklass.now
      assert custom_timeklass.now.respond_to? :custom_format_method
    end
  end

  def test_freeze_in_date_subclass_returns_mocked_subclass
    t = Time.local(2008, 10, 10, 10, 10, 10)
    custom_dateklass = Class.new(Date) do
      def custom_format_method() strftime('%F') end
    end

    Timecop.freeze(2008, 10, 10, 10, 10, 10) do
      assert custom_dateklass.today.is_a? custom_dateklass
      assert Date.today.eql? custom_dateklass.today
      assert custom_dateklass.today.respond_to? :custom_format_method
    end
  end

  def test_freeze_in_datetime_subclass_returns_mocked_subclass
    t = Time.local(2008, 10, 10, 10, 10, 10)
    custom_datetimeklass = Class.new(DateTime) do
      def custom_format_method() strftime('%F') end
    end

    Timecop.freeze(2008, 10, 10, 10, 10, 10) do
      assert custom_datetimeklass.now.is_a? custom_datetimeklass
      assert DateTime.now.eql? custom_datetimeklass.now
      assert custom_datetimeklass.now.respond_to? :custom_format_method
    end
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
    assert t != Time.now
  end

  def test_freeze_with_time_instance_works_as_expected
    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.freeze(t) do
      assert_equal t, Time.now
      assert_date_times_equal DateTime.new(2008, 10, 10, 10, 10, 10, local_offset), DateTime.now
      assert_equal Date.new(2008, 10, 10), Date.today
    end

    assert t != Time.now
    assert DateTime.new(2008, 10, 10, 10, 10, 10, local_offset) != DateTime.now
    assert Date.new(2008, 10, 10) != Date.today
  end

  def test_freeze_with_datetime_on_specific_timezone_during_dst
    each_timezone do
      # Start from a time that is subject to DST
      Timecop.freeze(2009, 9, 1)
      # Travel to a DateTime that is also in DST
      t = DateTime.parse("2009-10-11 00:38:00 +0200")
      Timecop.freeze(t) do
        assert_date_times_equal t, DateTime.now
      end
      Timecop.return
    end
  end

  def test_freeze_with_datetime_on_specific_timezone_not_during_dst
    each_timezone do
      # Start from a time that is not subject to DST
      Timecop.freeze(2009, 12, 1)
      # Travel to a time that is also not in DST
      t = DateTime.parse("2009-12-11 00:38:00 +0100")
      Timecop.freeze(t) do
        assert_date_times_equal t, DateTime.now
      end
    end
  end

  def test_freeze_with_datetime_from_a_non_dst_time_to_a_dst_time
    each_timezone do
      # Start from a time that is not subject to DST
      Timecop.freeze(DateTime.parse("2009-12-1 00:00:00 +0100"))
      # Travel back to a time in DST
      t = DateTime.parse("2009-10-11 00:38:00 +0200")
      Timecop.freeze(t) do
        assert_date_times_equal t, DateTime.now
      end
    end
  end

  def test_freeze_with_datetime_from_a_dst_time_to_a_non_dst_time
    each_timezone do
      # Start from a time that is not subject to DST
      Timecop.freeze(DateTime.parse("2009-10-11 00:00:00 +0200"))
      # Travel back to a time in DST
      t = DateTime.parse("2009-12-1 00:38:00 +0100")
      Timecop.freeze(t) do
        assert_date_times_equal t, DateTime.now
      end
    end
  end

  def test_freeze_with_date_instance_works_as_expected
    d = Date.new(2008, 10, 10)
    Timecop.freeze(d) do
      assert_equal d, Date.today
      assert_equal Time.local(2008, 10, 10, 0, 0, 0), Time.now
      assert_date_times_equal DateTime.new(2008, 10, 10, 0, 0, 0, local_offset), DateTime.now
    end
    assert d != Date.today
    assert Time.local(2008, 10, 10, 0, 0, 0) != Time.now
    assert DateTime.new(2008, 10, 10, 0, 0, 0, local_offset) != DateTime.now
  end

  def test_freeze_with_integer_instance_works_as_expected
    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.freeze(t) do
      assert_equal t, Time.now
      assert_date_times_equal DateTime.new(2008, 10, 10, 10, 10, 10, local_offset), DateTime.now
      assert_equal Date.new(2008, 10, 10), Date.today
      Timecop.freeze(10) do
        assert_equal t + 10, Time.now
        assert_equal Time.local(2008, 10, 10, 10, 10, 20), Time.now
        assert_equal Date.new(2008, 10, 10), Date.today
      end
    end
    assert t != Time.now
    assert DateTime.new(2008, 10, 10, 10, 10, 10) != DateTime.now
    assert Date.new(2008, 10, 10) != Date.today
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

  def test_exception_thrown_in_return_block_restores_previous_time
    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.freeze(t) do
      Timecop.return { raise 'foobar' } rescue nil
      assert_equal t, Time.now
    end
  end

  def test_freeze_freezes_time
    t = Time.local(2008, 10, 10, 10, 10, 10)
    now = Time.now
    Timecop.freeze(t) do
      #assert Time.now < now, "If we had failed to freeze, time would have proceeded, which is what appears to have happened."
      new_t, new_d, new_dt = Time.now, Date.today, DateTime.now
      assert_equal t, new_t, "Failed to freeze time." # 2 seconds
      #sleep(10)
      assert_equal new_t, Time.now
      assert_equal new_d, Date.today
      assert_equal new_dt, DateTime.now
    end
  end

  def test_travel_keeps_time_moving
    t = Time.local(2008, 10, 10, 10, 10, 10)
    now = Time.now
    Timecop.travel(t) do
      new_now = Time.now
      assert_times_effectively_equal(new_now, t, 1, "Looks like we failed to actually travel time")
      sleep(0.25)
      assert_times_effectively_not_equal new_now, Time.now, 0.24, "Looks like time is not moving"
    end
  end

  def test_mocked_date_time_now_is_local
    each_timezone do
      t = DateTime.parse("2009-10-11 00:38:00 +0200")
      Timecop.freeze(t) do
        if ENV['TZ'] == 'UTC'
          assert_equal(local_offset, 0, "Local offset not be zero for #{ENV['TZ']}")
        else
          assert(local_offset, 0 != "Local offset should not be zero for #{ENV['TZ']}")
        end
        assert_equal local_offset, DateTime.now.offset, "Failed for timezone: #{ENV['TZ']}"
      end
    end
  end

  def test_scaling_keeps_time_moving_at_an_accelerated_rate
    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.scale(4, t) do
      start = Time.now
      assert_times_effectively_equal start, t, 1, "Looks like we failed to actually travel time"
      sleep(0.25)
      assert_times_effectively_equal Time.at((start + 4*0.25).to_f), Time.now, 0.25, "Looks like time is not moving at 4x"
    end
  end

  def test_scaling_returns_now_if_no_block_given
    t = Time.local(2008, 10, 10, 10, 10, 10)
    assert_times_effectively_equal t, Timecop.scale(4, t)
  end

  def test_freeze_with_utc_time
    each_timezone do
      t = Time.utc(2008, 10, 10, 10, 10, 10)
      local = t.getlocal
      Timecop.freeze(t) do
        assert_equal local, Time.now, "Failed for timezone: #{ENV['TZ']}"
      end
    end
  end

  def test_freeze_without_arguments_instance_works_as_expected
    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.freeze(t) do
      assert_equal t, Time.now
      Timecop.freeze do
        assert_equal t, Time.now
        assert_equal Time.local(2008, 10, 10, 10, 10, 10), Time.now
        assert_equal Date.new(2008, 10, 10), Date.today
      end
    end
    assert t != Time.now
  end

  def test_destructive_methods_on_frozen_time
    # Use any time zone other than UTC.
    ENV['TZ'] = 'EST'

    t = Time.local(2008, 10, 10, 10, 10, 10)
    Timecop.freeze(t) do
      assert !Time.now.utc?, "Time#local failed to return a time in the local time zone."

      # #utc, #gmt, and #localtime are destructive methods.
      Time.now.utc

      assert !Time.now.utc?, "Failed to thwart destructive methods."
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

  def test_recursive_travel_yields_correct_time
    Timecop.travel(2008, 10, 10, 10, 10, 10) do
      Timecop.travel(2008, 9, 9, 9, 9, 9) do |inner_freeze|
        assert_times_effectively_equal inner_freeze, Time.now, 1, "Failed to yield current time back to block"
      end
    end
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

  def test_travel_time_returns_now_if_no_block_given
    t_future = Time.local(2030, 10, 10, 10, 10, 10)
    assert_times_effectively_equal t_future, Timecop.travel(t_future)
  end

  def test_return_temporarily_returns_to_current_time_in_given_block
    time_after_travel = Time.local(1990, 7, 16)
    now = Time.now

    Timecop.travel(time_after_travel)

    assert_times_effectively_equal(time_after_travel, Time.now)
    Timecop.return do
      assert_times_effectively_equal(now, Time.now)
    end
    assert_times_effectively_equal(time_after_travel, Time.now)
  end

  def test_travel_time_with_block_returns_the_value_of_the_block
    t_future = Time.local(2030, 10, 10, 10, 10, 10)
    expected = :foo
    actual = Timecop.travel(t_future) { expected }

    assert_equal expected, actual
  end

  def test_freeze_time_returns_now_if_no_block_given
    t_future = Time.local(2030, 10, 10, 10, 10, 10)
    assert_times_effectively_equal t_future, Timecop.freeze(t_future)
  end

  def test_freeze_time_with_block_returns_the_value_of_the_block
    t_future = Time.local(2030, 10, 10, 10, 10, 10)
    expected = :foo
    actual = Timecop.freeze(t_future) { expected }

    assert_equal expected, actual
  end

  def test_return_returns_nil
    assert_nil Timecop.return
  end

  def test_freeze_without_params
    Timecop.freeze 1 do
      current_time = Time.now
      Timecop.freeze do
        assert_equal Time.now, current_time
      end
    end
  end

  def test_freeze_with_new_date
    date = Date.new(2012, 6, 9)
    Timecop.freeze(Date.new(2012, 6, 9)) do
      assert_equal date, Time.now.__send__(:to_date)
    end
  end

  def test_return_to_baseline_without_a_baseline_set_returns_to_current_time
    time_before_travel = Time.now
    Timecop.travel Time.now - 60
    Timecop.return_to_baseline
    assert times_effectively_equal(time_before_travel, Time.now)
  end

  def test_return_to_baseline_with_a_baseline_set_returns_to_baseline
    baseline = Time.local(1945, 10, 10, 10, 10, 10)
    Timecop.baseline = baseline
    Timecop.travel Time.now - 60
    time_now = Timecop.return_to_baseline
    assert times_effectively_equal(baseline, time_now),
      "expected to return to #{baseline}, but returned to #{time_now}"
  end

  def test_return_eliminates_baseline
    time_before_travel = Time.now
    Timecop.baseline = Time.local(1937, 9, 9, 9, 9, 9)
    Timecop.return
    assert times_effectively_equal(time_before_travel, Time.now)

    Timecop.travel(Time.now - 100)
    Timecop.return_to_baseline
    assert times_effectively_equal(time_before_travel, Time.now)
  end

  def test_mock_time_new_same_as_now
    date = Time.local(2011, 01, 02)
    Timecop.freeze date
    assert_equal date, Time.now
    assert_equal date, Time.new
  end

  def test_not_callable_send_travel
    assert_raises NoMethodError do
      Timecop.send_travel(:travel, Time.now - 100)
    end
  end

  def test_datetime_to_time_for_dst_to_non_dst
    # Start at a time subject to DST
    Timecop.travel(2009, 4, 1, 0, 0, 0, -4*60*60) do

      # Then freeze, via DateTime, at a time not subject to DST
      t = DateTime.new(2009,01,01,0,0,0, "-0500")
      Timecop.freeze(t) do

        # Check the current time via DateTime.now--should be what we asked for
        assert_date_times_equal t, DateTime.now

        # Then check the current time via Time.now (not DateTime.now)
        assert_times_effectively_equal Time.new(2009, 1, 1, 0, 0, 0, -5*60*60), Time.now
      end
    end
  end

  def test_raises_when_safe_mode_and_no_block
    with_safe_mode do
      assert_raises Timecop::SafeModeException do
        Timecop.freeze
      end
    end
  end

  def test_raises_when_safe_mode_and_no_block_though_previously_block_given
    Timecop.freeze do
      Timecop.freeze
    end

    with_safe_mode do
      assert_raises Timecop::SafeModeException do
        Timecop.freeze
      end
    end
  end

  def test_no_raise_when_safe_mode_and_block_used
    with_safe_mode do
      Timecop.freeze {}
    end
  end

  def test_no_raise_when_not_safe_mode_and_no_block
    with_safe_mode(false) do
      Timecop.freeze
    end
  end

  def test_no_raise_when_safe_mode_and_no_block_and_in_block_context
    with_safe_mode do
      Timecop.freeze do
        Timecop.freeze
      end
    end
  end

  def test_date_strptime_without_year
    Timecop.freeze(Time.new(1984,2,28)) do
      assert_equal Date.strptime('04-14', '%m-%d'), Date.new(1984, 4, 14)
    end
  end

  def test_date_strptime_without_specifying_format
    Timecop.freeze(Time.new(1984,2,28)) do
      assert_equal Date.strptime('1999-04-14'), Date.new(1999, 4, 14)
    end
  end

  def test_frozen_after_freeze
    Timecop.freeze
    assert Timecop.frozen?
  end

  def test_frozen_inside_freeze
    Timecop.freeze do
      assert Timecop.frozen?
    end
  end

  def test_not_frozen_after_return
    Timecop.freeze
    Timecop.return
    assert !Timecop.frozen?
  end

  def test_thread_safe_timecop
    Timecop.thread_safe = true
    date = Time.local(2011, 01, 02)
    thread = Thread.new do
      Timecop.freeze(date) do
        sleep 1 #give main thread time to run
        assert_equal date, Time.now
      end
    end

    sleep 0.25
    assert Time.now != date
    thread.join
  ensure
    Timecop.thread_safe = false
  end

  private

  def with_safe_mode(enabled=true)
    mode = Timecop.safe_mode?
    Timecop.safe_mode = enabled
    yield
  ensure
    Timecop.safe_mode = mode
  end
end
