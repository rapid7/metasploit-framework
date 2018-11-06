module Faker
  class Measurement < Base
    class << self
      ALL = 'all'.freeze
      NONE = 'none'.freeze

      def height(amount = rand(10))
        define_measurement_locale(amount, 'height')
      end

      def length(amount = rand(10))
        define_measurement_locale(amount, 'length')
      end

      def volume(amount = rand(10))
        define_measurement_locale(amount, 'volume')
      end

      def weight(amount = rand(10))
        define_measurement_locale(amount, 'weight')
      end

      def metric_height(amount = rand(10))
        define_measurement_locale(amount, 'metric_height')
      end

      def metric_length(amount = rand(10))
        define_measurement_locale(amount, 'metric_length')
      end

      def metric_volume(amount = rand(10))
        define_measurement_locale(amount, 'metric_volume')
      end

      def metric_weight(amount = rand(10))
        define_measurement_locale(amount, 'metric_weight')
      end

      private

      def check_for_plural(text, number)
        if number && number != 1
          make_plural(text)
        else
          text
        end
      end

      def define_measurement_locale(amount, locale)
        ensure_valid_amount(amount)
        if amount == ALL
          make_plural(fetch("measurement.#{locale}"))
        elsif amount == NONE
          fetch("measurement.#{locale}")
        else
          locale = check_for_plural(fetch("measurement.#{locale}"), amount)

          "#{amount} #{locale}"
        end
      end

      def ensure_valid_amount(amount)
        raise ArgumentError, 'invalid amount' unless amount == NONE || amount == ALL || amount.is_a?(Integer) || amount.is_a?(Float)
      end

      def make_plural(text)
        case text
        when 'foot'
          'feet'
        when 'inch'
          'inches'
        when 'fluid ounce'
          'fluid ounces'
        when 'metric ton'
          'metric tons'
        else
          "#{text}s"
        end
      end
    end
  end
end
