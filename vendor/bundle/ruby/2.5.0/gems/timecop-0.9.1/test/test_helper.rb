require 'bundler/setup'
require 'minitest/autorun'
require 'minitest/rg'

$VERBOSE = true # enable ruby warnings

require 'mocha/setup'

class Minitest::Test
  private
    # Tests to see that two times are within the given distance,
    # in seconds, from each other.
    def times_effectively_equal(time1, time2, seconds_interval = 1)
      (time1 - time2).abs <= seconds_interval
    end

    def assert_times_effectively_equal(time1, time2, seconds_interval = 1, msg = nil)
      assert times_effectively_equal(time1, time2, seconds_interval), "#{msg}: time1 = #{time1.to_s}, time2 = #{time2.to_s}"
    end

    def assert_times_effectively_not_equal(time1, time2, seconds_interval = 1, msg = nil)
      assert !times_effectively_equal(time1, time2, seconds_interval), "#{msg}: time1 = #{time1.to_s}, time2 = #{time2.to_s}"
    end

    # Gets the local offset (supplied by ENV['TZ'] or your computer's clock)
    # At the given timestamp, or Time.now if not time is given.
    def local_offset(time = Time.now)
      Time.at(time.to_i).to_datetime.offset
    end

    TIMEZONES = ["Europe/Paris", "UTC", "America/Chicago"]

    def each_timezone
      old_tz = ENV["TZ"]

      begin
        TIMEZONES.each do |timezone|
          ENV["TZ"] = timezone
          yield
        end
      ensure
        ENV["TZ"] = old_tz
      end
    end

    def a_time_stack_item
      Timecop::TimeStackItem.new(:freeze, 2008, 1, 1, 0, 0, 0)
    end

    def assert_date_times_equal(dt1, dt2)
      assert_in_delta dt1.to_time.to_f, dt2.to_time.to_f, 0.01, "Failed for timezone: #{ENV['TZ']}: #{dt1.to_s} not equal to #{dt2.to_s}"
    end

    def jruby?
      RUBY_PLATFORM == "java"
    end

end
