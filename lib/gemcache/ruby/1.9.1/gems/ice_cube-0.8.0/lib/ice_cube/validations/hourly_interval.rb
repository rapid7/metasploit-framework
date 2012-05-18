module IceCube

  module Validations::HourlyInterval

    def interval(interval)
      validations_for(:interval) << Validation.new(interval)
      clobber_base_validations(:hour)
      self
    end

    class Validation

      attr_reader :interval

      def type
        :hour
      end

      def build_s(builder)
        builder.base = interval == 1 ? 'Hourly' : "Every #{interval} hours"
      end

      def build_hash(builder)
        builder[:interval] = interval
      end

      def build_ical(builder)
        builder['FREQ'] << 'HOURLY'
        unless interval == 1
          builder['INTERVAL'] << interval
        end
      end

      def initialize(interval)
        @interval = interval
      end

      def dst_adjust?
        false
      end

      def validate(time, schedule)
        start_time = schedule.start_time
        sec = (time.to_i - time.to_i % ONE_HOUR) - 
          (start_time.to_i - start_time.to_i % ONE_HOUR)
        hours = sec / ONE_HOUR
        unless hours % interval == 0
          interval - (hours % interval)
        end
      end

    end

  end

end
