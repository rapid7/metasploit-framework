module IceCube

  module Validations::MinuteOfHour

    include Validations::Lock

    def minute_of_hour(*minutes)
      minutes.each do |minute|
        validations_for(:minute_of_hour) << Validation.new(minute)
      end
      clobber_base_validations(:min)
      self
    end

    class Validation

      include Validations::Lock

      StringBuilder.register_formatter(:minute_of_hour) do |segments|
        str = "on the #{StringBuilder.sentence(segments)} "
        str << (segments.size == 1 ? 'minute of the hour' : 'minutes of the hour')
      end

      attr_reader :minute
      alias :value :minute

      def initialize(minute)
        @minute = minute
      end

      def build_s(builder)
        builder.piece(:minute_of_hour) << StringBuilder.nice_number(minute)
      end

      def type
        :min
      end

      def build_hash(builder)
        builder.validations_array(:minute_of_hour) << minute
      end

      def build_ical(builder)
        builder['BYMINUTE'] << minute
      end

    end

  end

end
