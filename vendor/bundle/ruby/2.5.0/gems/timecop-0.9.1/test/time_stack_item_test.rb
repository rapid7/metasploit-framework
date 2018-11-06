require 'date'
require_relative "test_helper"
require 'timecop'

require 'active_support/all'

class TestTimeStackItem < Minitest::Test
  def teardown
    Timecop.return
    Time.zone = nil
  end

  def test_new_with_time
    t = Time.now
    y, m, d, h, min, s = t.year, t.month, t.day, t.hour, t.min, t.sec
    stack_item = Timecop::TimeStackItem.new(:freeze, t)

    assert_equal y,   stack_item.year
    assert_equal m,   stack_item.month
    assert_equal d,   stack_item.day
    assert_equal h,   stack_item.hour
    assert_equal min, stack_item.min
    assert_equal s,   stack_item.sec
  end

  def test_new_with_time_and_arguments
    t = Time.new(2012, 7, 28, 20, 0)
    y, m, d, h, min, s = t.year, t.month, t.day, t.hour, t.min, t.sec
    stack_item = Timecop::TimeStackItem.new(:freeze, t)

    assert_equal y,   stack_item.year
    assert_equal m,   stack_item.month
    assert_equal d,   stack_item.day
    assert_equal h,   stack_item.hour
    assert_equal min, stack_item.min
    assert_equal s,   stack_item.sec
  end

  def test_new_with_datetime_now
    t = DateTime.now
    y, m, d, h, min, s = t.year, t.month, t.day, t.hour, t.min, t.sec
    stack_item = Timecop::TimeStackItem.new(:freeze, t)

    assert_equal y,   stack_item.year
    assert_equal m,   stack_item.month
    assert_equal d,   stack_item.day
    assert_equal h,   stack_item.hour
    assert_equal min, stack_item.min
    assert_equal s,   stack_item.sec
  end

  def test_new_with_datetime_in_different_timezone
    each_timezone do
      t = DateTime.parse("2009-10-11 00:38:00 +0200")
      stack_item = Timecop::TimeStackItem.new(:freeze, t)

      assert_date_times_equal(t, stack_item.datetime)
    end
  end

  def test_new_with_date
    date = Date.today
    y, m, d, h, min, s = date.year, date.month, date.day, 0, 0, 0
    stack_item = Timecop::TimeStackItem.new(:freeze, date)

    assert_equal y,   stack_item.year
    assert_equal m,   stack_item.month
    assert_equal d,   stack_item.day
    assert_equal h,   stack_item.hour
    assert_equal min, stack_item.min
    assert_equal s,   stack_item.sec
  end

  # Due to the nature of this test (calling Time.now once in this test and
  # once in #new), this test may fail when two subsequent calls
  # to Time.now return a different second.
  def test_new_with_integer
    t = Time.now
    y, m, d, h, min, s = t.year, t.month, t.day, t.hour, t.min, t.sec
    stack_item = Timecop::TimeStackItem.new(:freeze, 0)

    assert_equal y,   stack_item.year
    assert_equal m,   stack_item.month
    assert_equal d,   stack_item.day
    assert_equal h,   stack_item.hour
    assert_equal min, stack_item.min
    assert_equal s,   stack_item.sec
  end

  def test_new_with_float
    t = Time.now
    y, m, d, h, min, s = t.year, t.month, t.day, t.hour, t.min, t.sec
    stack_item = Timecop::TimeStackItem.new(:freeze, 0.0)

    assert_equal y,   stack_item.year
    assert_equal m,   stack_item.month
    assert_equal d,   stack_item.day
    assert_equal h,   stack_item.hour
    assert_equal min, stack_item.min
    assert_equal s,   stack_item.sec
  end

  def test_new_with_individual_arguments
    y, m, d, h, min, s = 2008, 10, 10, 10, 10, 10
    stack_item = Timecop::TimeStackItem.new(:freeze, y, m, d, h, min, s)

    assert_equal y,   stack_item.year
    assert_equal m,   stack_item.month
    assert_equal d,   stack_item.day
    assert_equal h,   stack_item.hour
    assert_equal min, stack_item.min
    assert_equal s,   stack_item.sec
  end

  def test_rational_to_utc_offset
    assert_equal -14400, a_time_stack_item.send(:rational_to_utc_offset, Rational(-1, 6))
    assert_equal -18000, a_time_stack_item.send(:rational_to_utc_offset, Rational(-5, 24))
    assert_equal 0,      a_time_stack_item.send(:rational_to_utc_offset, Rational(0, 1))
    assert_equal 3600,   a_time_stack_item.send(:rational_to_utc_offset, Rational(1, 24))
  end

  def test_utc_offset_to_rational
    assert_equal Rational(-1, 6),  a_time_stack_item.send(:utc_offset_to_rational, -14400)
    assert_equal Rational(-5, 24), a_time_stack_item.send(:utc_offset_to_rational, -18000)
    assert_equal Rational(0, 1),   a_time_stack_item.send(:utc_offset_to_rational, 0)
    assert_equal Rational(1, 24),  a_time_stack_item.send(:utc_offset_to_rational, 3600)
  end

  def test_datetime_in_presence_of_activesupport_timezone
    skip('requires ActiveSupport') unless Time.respond_to? :zone
    backed_up_zone, backed_up_tzvar = Time.zone, ENV['TZ']

    Time.zone = ENV['TZ'] = 'America/Los_Angeles'
    t = DateTime.new(2001, 2, 28, 23, 59, 59.5)
    tsi = Timecop::TimeStackItem.new(:freeze, t)

    assert_date_times_equal t, tsi.datetime
  ensure
    Time.zone, ENV['TZ'] = backed_up_zone, backed_up_tzvar
  end

  # Ensure DateTimes handle changing DST properly
  def test_datetime_for_dst_to_non_dst
    Timecop.freeze(DateTime.parse("2009-12-1 00:38:00 -0500"))
    t = DateTime.parse("2009-10-11 00:00:00 -0400")
    tsi = Timecop::TimeStackItem.new(:freeze, t)

    assert_date_times_equal t, tsi.datetime
  end

  # Ensure DateTimes handle changing DST properly when changing from DateTime to Time
  def test_datetime_for_dst_to_time_for_non_dst
    Timecop.freeze(DateTime.parse("2009-12-1 00:38:00 -0500"))
    t = DateTime.parse("2009-10-11 00:00:00 -0400")
    tsi = Timecop::TimeStackItem.new(:freeze, t)

    assert_date_times_equal t.to_time, tsi.time
  end

  def test_datetime_for_non_dst_to_dst
    Timecop.freeze(DateTime.parse("2009-10-11 00:00:00 -0400"))
    t = DateTime.parse("2009-11-30 23:38:00 -0500")
    tsi = Timecop::TimeStackItem.new(:freeze, t)
    return if !tsi.time.dst?

    assert_date_times_equal t, tsi.datetime
    assert_equal Date.new(2009, 12, 1), tsi.date
  end

  def test_set_travel_offset_for_travel
    t_now = Time.now
    t = Time.local(2009, 10, 1, 0, 0, 30)
    expected_offset = t - t_now
    tsi = Timecop::TimeStackItem.new(:travel, t)

    assert_times_effectively_equal expected_offset, tsi.send(:travel_offset), 1, "Offset not calculated correctly"
  end

  def test_set_travel_offset_for_freeze
    Timecop.freeze(2009, 10, 1, 0, 0, 0)
    t = Time.local(2009, 10, 1, 0, 0, 30)
    tsi = Timecop::TimeStackItem.new(:freeze, t)

    assert_equal nil, tsi.send(:travel_offset)
  end

  def test_timezones
    Time.zone = "Europe/Zurich"
    time = Time.zone.parse("2012-12-27T12:12:12+08:00")
    Timecop.freeze(time) do |frozen_time|
      assert_equal time, frozen_time
    end
  end

  def test_timezones_with_parsed_string
    Time.zone = "Europe/Zurich"
    time_string = "2012-12-27 12:12"
    expected_time = Time.zone.parse(time_string)
    Timecop.freeze(time_string) do |frozen_time|
      assert_equal expected_time, frozen_time
    end
  end

  def test_timezones_apply_dates
    Time.zone = "Central Time (US & Canada)"
    time = Time.zone.local(2013,1,3)

    Timecop.freeze(time) do
      assert_equal time.to_date, Time.now.to_date
    end
  end

  def test_set_scaling_factor_for_scale
    t_now = Time.now
    t = Time.local(2009, 10, 1, 0, 0, 30)
    expected_offset = t - t_now
    tsi = Timecop::TimeStackItem.new(:scale, 4, t)

    assert_times_effectively_equal expected_offset, tsi.send(:travel_offset), 1, "Offset not calculated correctly"
    assert_equal tsi.send(:scaling_factor), 4, "Scaling factor not set"
  end

  def test_parse_only_string_with_active_support
    Time.expects(:parse).never
    Timecop.freeze(2011, 01, 02, hour=0, minute=0, second=0)
  end

  def test_parse_date
    Timecop.freeze(Date.new(2012, 6, 9))
  end

  def test_time_zone_returns_nil
    Time.zone = nil
    Timecop.freeze
  end

  def test_nsecs_are_set
    time = Time.now
    Timecop.freeze time
    assert_equal time, Time.now
    assert_equal time.nsec, Time.now.nsec if (Time.now.respond_to?(:nsec))
  end

  def test_time_with_different_timezone_keeps_nsec
    Time.zone = "Tokyo"
    t = Time.now
    Timecop.freeze(t) do
      assert_equal t, Time.now
      assert_equal t.nsec, Time.now.nsec if (Time.now.respond_to?(:nsec))
    end
  end

  def test_time_now_always_returns_local_time
    Time.zone = "Tokyo"
    t = Time.utc(2000, 1, 1)
    Timecop.freeze(t) do
      assert_equal t.getlocal.zone, Time.now.zone
    end
  end

  def test_time_zone_now_returns_time_in_that_zone
    Time.zone = "Hawaii"
    t = Time.utc(2000, 1, 1)
    Timecop.freeze(t) do
      assert_equal t, Time.zone.now
      assert_equal 'HST', Time.zone.now.zone
    end
  end

  def test_freezing_a_time_leaves_timezone_intact
    Time.zone = "Tokyo"
    t = Time.now
    t_dup = t.dup
    Timecop.freeze(t) {}
    assert_equal t_dup.zone, t.zone
  end

  def test_freezing_a_time_with_zone_returns_proper_zones
    Time.zone = "Hawaii"
    t = ActiveSupport::TimeWithZone.new(Time.utc(2000, 1, 1), ActiveSupport::TimeZone['Tokyo'])
    Timecop.freeze(t) do
      local_now = Time.now
      assert_equal t, local_now
      assert_equal t.getlocal.zone, local_now.zone

      zoned_now = Time.zone.now
      assert_equal t, zoned_now
      assert_equal 'HST', zoned_now.zone
    end
  end

  def test_datetime_timezones
    dt = DateTime.new(2011,1,3,15,25,0,"-6")
    Timecop.freeze(dt) do
      now = DateTime.now
      assert_equal dt, now, "#{dt.to_f}, #{now.to_f}"
    end
  end
end
