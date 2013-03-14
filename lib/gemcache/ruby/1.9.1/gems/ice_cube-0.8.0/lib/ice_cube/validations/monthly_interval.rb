module IceCube

  module Validations::MonthlyInterval

    def interval(interval = 1)
      validations_for(:interval) << Validation.new(interval)
      clobber_base_validations(:month)
      self
    end

    class Validation

      attr_reader :interval

      def type
        :month
      end

      def build_s(builder)
        builder.base = interval == 1 ? 'Monthly' : "Every #{interval} months"
      end

      def build_ical(builder)
        builder['FREQ'] << 'MONTHLY'
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
        months_to_start = (time.month - start_time.month) + (time.year - start_time.year) * 12
        unless months_to_start % interval == 0
          interval - (months_to_start % interval)
        end
      end

    end

  end

end
