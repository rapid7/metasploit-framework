module IceCube

  module Validations::Until

    extend ::Deprecated

    # accessor
    def until_time
      @until
    end
    deprecated_alias :until_date, :until_time

    def until(time)
      @until = time
      replace_validations_for(:until, [Validation.new(time)])
      self
    end

    class Validation

      attr_reader :time

      def type
        :dealbreaker
      end

      def initialize(time)
        @time = time
      end

      def build_ical(builder)
        builder['UNTIL'] << IcalBuilder.ical_utc_format(time)
      end

      def build_hash(builder)
        builder[:until] = TimeUtil.serialize_time(time)
      end

      def build_s(builder)
        builder.piece(:until) << "until #{time.strftime(TO_S_TIME_FORMAT)}"
      end

      def validate(t, schedule)
        raise UntilExceeded if t > time 
      end

    end
      
  end

end
