module IceCube

  module Validations::Count

    # accessor
    def occurrence_count
      @count
    end

    def count(max)
      @count = max
      replace_validations_for(:count, [Validation.new(max, self)]) # replace
      self
    end

    class Validation

      attr_reader :rule, :count

      def initialize(count, rule)
        @count = count
        @rule = rule
      end

      def type
        :dealbreaker
      end

      def validate(time, schedule)
        if rule.uses && rule.uses >= count
          raise CountExceeded
        end
      end

      def build_s(builder)
        builder.piece(:count) << count
      end

      def build_hash(builder)
        builder[:count] = count
      end

      def build_ical(builder)
        builder['COUNT'] << count
      end

      StringBuilder.register_formatter(:count) do |segments|
        count = segments.first 
        "#{count} #{count == 1 ? 'time' : 'times'}"
      end

    end

  end

end
