require 'date'

module IceCube

  module TimeUtil

    LEAP_YEAR_MONTH_DAYS = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    COMMON_YEAR_MONTH_DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    DAYS = {
      :sunday => 0, :monday => 1, :tuesday => 2, :wednesday => 3,
      :thursday => 4, :friday => 5, :saturday => 6
    }

    MONTHS = {
      :january => 1, :february => 2, :march => 3, :april => 4, :may => 5,
      :june => 6, :july => 7, :august => 8, :september => 9, :october => 10,
      :november => 11, :december => 12
    }

    # Serialize a time appropriate for storing
    def self.serialize_time(time)
      if defined?(:ActiveSupport) && const_defined?(:ActiveSupport) && time.is_a?(ActiveSupport::TimeWithZone)
        { :time => time.utc, :zone => time.time_zone.name }
      elsif time.is_a?(Time)
        time
      end
    end

    # Deserialize a time serialized with serialize_time
    def self.deserialize_time(time_or_hash)
      if time_or_hash.is_a?(Time)
        time_or_hash
      elsif time_or_hash.is_a?(Hash)
        time_or_hash[:time].in_time_zone(time_or_hash[:zone])
      end
    end

    # Get the beginning of a date
    def self.beginning_of_date(date)
      date.respond_to?(:beginning_of_day) ?
        date.beginning_of_day :
        Time.local(date.year, date.month, date.day, 0, 0, 0)
    end

    # Get the end of a date
    def self.end_of_date(date)
      date.respond_to?(:end_of_day) ?
        date.end_of_day :
        Time.local(date.year, date.month, date.day, 23, 59, 59)
    end

    # Convert a symbol to a numeric month
    def self.symbol_to_month(sym)
      month = MONTHS[sym]
      raise "No such month: #{sym}" unless month
      month
    end

    # Convert a symbol to a numeric day
    def self.symbol_to_day(sym)
      day = DAYS[sym]
      raise "No such day: #{sym}" unless day
      day
    end

    # Convert a symbol to an ical day (SU, MO)
    def self.week_start(sym)
      raise "No such day: #{sym}" unless DAYS.keys.include?(sym)
      day = sym.to_s.upcase[0..1]
      day
    end

    # Convert weekday from base sunday to the schedule's week start.
    def self.normalize_weekday(daynum, week_start)
      (daynum - symbol_to_day(week_start)) % 7
    end

    # Return the count of the number of times wday appears in the month,
    # and which of those time falls on
    def self.which_occurrence_in_month(time, wday)
      first_occurrence = ((7 - Time.utc(time.year, time.month, 1).wday) + time.wday) % 7 + 1
      this_weekday_in_month_count = ((days_in_month(time) - first_occurrence + 1) / 7.0).ceil
      nth_occurrence_of_weekday = (time.mday - first_occurrence) / 7 + 1
      [nth_occurrence_of_weekday, this_weekday_in_month_count]
    end

    # Get the days in the month for +time
    def self.days_in_month(time)
      days_in_month_year(time.month, time.year)
    end

    def self.days_in_next_month(time)
      # Get the next month
      year = time.year
      month = time.month + 1
      if month > 12
        month %= 12
        year += 1
      end
      # And then determine
      days_in_month_year(month, year)
    end

    def self.days_in_month_year(month, year)
      is_leap?(year) ? LEAP_YEAR_MONTH_DAYS[month - 1] : COMMON_YEAR_MONTH_DAYS[month - 1]
    end

    # Number of days in a year
    def self.days_in_year(time)
      is_leap?(time.year) ? 366 : 365
    end

    # Number of days to n years
    def self.days_in_n_years(time, year_distance)
      sum = 0
      wrapper = TimeWrapper.new(time)
      year_distance.times do
        diy = days_in_year(wrapper.to_time)
        sum += diy
        wrapper.add(:day, diy)
      end
      sum
    end

    # The number of days in n months
    def self.days_in_n_months(time, month_distance)
      # move to a safe spot in the month to make this computation
      desired_day = time.day
      time -= IceCube::ONE_DAY * (time.day - 27) if time.day >= 28
      # move n months ahead
      sum = 0
      wrapper = TimeWrapper.new(time)
      month_distance.times do
        dim = days_in_month(wrapper.to_time)
        sum += dim
        wrapper.add(:day, dim)
      end
      # now we can move to the desired day
      dim = days_in_month(wrapper.to_time)
      if desired_day > dim
        sum -= desired_day - dim
      end
      sum
    end

    # Given a year, return a boolean indicating whether it is
    # a leap year or not
    def self.is_leap?(year)
      (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    end

    # A utility class for safely moving time around
    class TimeWrapper

      def initialize(time, dst_adjust = true)
        @dst_adjust = dst_adjust
        @time = time
      end

      # Get the wrapper time back
      def to_time
        @time
      end

      # DST-safely add an interval of time to the wrapped time
      def add(type, val)
        type = :day if type == :wday
        adjust do
          @time += case type
          when :year then TimeUtil.days_in_n_years(@time, val) * ONE_DAY
          when :month then TimeUtil.days_in_n_months(@time, val) * ONE_DAY
          when :day  then val * ONE_DAY
          when :hour then val * ONE_HOUR
          when :min  then val * ONE_MINUTE
          when :sec  then val
          end
        end
      end

      # Clear everything below a certain type
      CLEAR_ORDER = [:sec, :min, :hour, :day, :month, :year]
      def clear_below(type)
        type = :day if type == :wday
        CLEAR_ORDER.each do |ptype|
          break if ptype == type
          adjust do
            send(:"clear_#{ptype}")
          end
        end
      end

      private

      def adjust(&block)
        if @dst_adjust
          off = @time.utc_offset
          yield
          diff = off - @time.utc_offset
          @time += diff if diff != 0
        else
          yield
        end
      end

      def clear_sec
        @time -= @time.sec
      end

      def clear_min
        @time -= (@time.min * ONE_MINUTE)
      end

      def clear_hour
        @time -= (@time.hour * ONE_HOUR)
      end

      # Move to the first of the month, 0 hours
      def clear_day
        @time -= (@time.day - 1) * IceCube::ONE_DAY
      end

      # Clear to january 1st
      def clear_month
        @time -= ONE_DAY
        until @time.month == 12
          @time -= TimeUtil.days_in_month(@time) * ONE_DAY
        end
        @time += ONE_DAY
      end

      def clear_year
      end

    end

  end

end
