module IceCube

  module Validations::YearlyInterval

    def interval(interval = 1)
      validations_for(:interval) << Validation.new(interval)
      clobber_base_validations(:year)
    end

    class Validation

      attr_reader :interval

      def type
        :year
      end

      def build_s(builder)
        builder.base = interval == 1 ? 'Yearly' : "Every #{interval} years"
      end

      def build_hash(builder)
        builder[:interval] = interval
      end

      def build_ical(builder)
        builder['FREQ'] << 'YEARLY'
        unless interval == 1
          builder['INTERVAL'] << interval
        end
      end

      def initialize(interval)
        @interval = interval
      end

      def validate(time, schedule)
        years_to_start = time.year - schedule.start_time.year
        unless years_to_start % interval == 0
          interval - (years_to_start % interval)
        end
      end

    end

  end

end
