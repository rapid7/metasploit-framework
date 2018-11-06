module Faker
  class Demographic < Base
    class << self
      def race
        fetch('demographic.race')
      end

      def educational_attainment
        fetch('demographic.educational_attainment')
      end

      def demonym
        fetch('demographic.demonym')
      end

      def marital_status
        fetch('demographic.marital_status')
      end

      def sex
        fetch('demographic.sex')
      end

      def height(unit = :metric)
        case unit
        when :imperial
          inches = rand_in_range(57, 86)
          "#{inches / 12} ft, #{inches % 12} in"
        when :metric
          rand_in_range(1.45, 2.13).round(2).to_s
        end
      end
    end
  end
end
