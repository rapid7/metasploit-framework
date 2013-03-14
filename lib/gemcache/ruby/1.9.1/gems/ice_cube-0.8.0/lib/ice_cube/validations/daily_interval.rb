module IceCube

  module Validations::DailyInterval

    # Add a new interval validation
    def interval(interval)
      validations_for(:interval) << Validation.new(interval)
      clobber_base_validations(:wday, :day)
      self
    end

    # A validation for checking to make sure that a time
    # is inside of a certain DailyInterval
    class Validation

      attr_reader :interval

      def initialize(interval)
        @interval = interval
      end

      def build_s(builder)
        builder.base = interval == 1 ? 'Daily' : "Every #{interval} days"
      end

      def build_hash(builder)
        builder[:interval] = interval
      end

      def build_ical(builder)
        builder['FREQ'] << 'DAILY'
        unless interval == 1
          builder['INTERVAL'] << interval
        end
      end

      def type
        :day
      end

      def validate(time, schedule)
        time_date = Date.new(time.year, time.month, time.day)
        start_date = Date.new(schedule.start_time.year, schedule.start_time.month, schedule.start_time.day)
        days = time_date - start_date
        unless days % interval === 0
          interval - (days % interval)
        end
      end

    end

  end

end
