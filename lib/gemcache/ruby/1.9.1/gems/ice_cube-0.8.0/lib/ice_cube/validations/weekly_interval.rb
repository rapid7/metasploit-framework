require 'date'

module IceCube

  module Validations::WeeklyInterval

    def interval(interval, week_start = :sunday)
      validations_for(:interval) << Validation.new(interval, week_start)
      clobber_base_validations(:day)
      self
    end

    class Validation

      attr_reader :interval, :week_start

      def type
        :day
      end

      def build_s(builder)
        builder.base = interval == 1 ? 'Weekly' : "Every #{interval} weeks"
      end

      def build_ical(builder)
        builder['FREQ'] << 'WEEKLY'
        unless interval == 1
          builder['INTERVAL'] << interval
          builder['WKST'] << TimeUtil.week_start(week_start)
        end
      end

      def build_hash(builder)
        builder[:interval] = interval
      end

      def initialize(interval, week_start)
        @interval = interval
        @week_start = week_start
      end

      def validate(time, schedule)
        date = Date.new(time.year, time.month, time.day)
        st = schedule.start_time
        start_date = Date.new(st.year, st.month, st.day)
        weeks = (
          (date - TimeUtil.normalize_weekday(date.wday, week_start)) - 
          (start_date - TimeUtil.normalize_weekday(start_date.wday, week_start))
        ) / 7
        unless weeks % interval == 0
          (interval - (weeks % interval)) * 7
        end
      end

    end

  end

end
