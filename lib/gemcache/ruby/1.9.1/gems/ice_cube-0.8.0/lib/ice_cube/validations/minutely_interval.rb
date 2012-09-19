module IceCube

  module Validations::MinutelyInterval

    def interval(interval)
      validations_for(:interval) << Validation.new(interval)
      clobber_base_validations(:min)
      self
    end

    class Validation

      attr_reader :interval

      def type
        :min
      end

      def dst_adjust?
        false
      end

      def build_s(builder)
        builder.base = interval == 1 ? 'Minutely' : "Every #{interval} minutes"
      end

      def build_ical(builder)
        builder['FREQ'] << 'MINUTELY'
        unless interval == 1
          builder['INTERVAL'] << interval
        end
      end

      def build_hash(builder)
        builder[:interval] = interval
      end

      def initialize(interval)
        @interval = interval
      end

      def validate(time, schedule)
        start_time = schedule.start_time
        sec = (time.to_i - time.to_i % ONE_MINUTE) -
          (start_time.to_i - start_time.to_i % ONE_MINUTE)
        minutes = sec / ONE_MINUTE
        unless minutes % interval == 0
          interval - (minutes % interval)
        end
      end

    end

  end

end
