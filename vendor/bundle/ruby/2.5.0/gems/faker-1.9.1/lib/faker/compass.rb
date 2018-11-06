module Faker
  class Compass < Base
    class << self
      def cardinal
        fetch('compass.cardinal.word')
      end

      def ordinal
        fetch('compass.ordinal.word')
      end

      def half_wind
        fetch('compass.half-wind.word')
      end

      def quarter_wind
        fetch('compass.quarter-wind.word')
      end

      def direction
        parse('compass.direction')
      end

      def abbreviation
        parse('compass.abbreviation')
      end

      def azimuth
        parse('compass.azimuth')
      end

      def cardinal_abbreviation
        fetch('compass.cardinal.abbreviation')
      end

      def ordinal_abbreviation
        fetch('compass.ordinal.abbreviation')
      end

      def half_wind_abbreviation
        fetch('compass.half-wind.abbreviation')
      end

      def quarter_wind_abbreviation
        fetch('compass.quarter-wind.abbreviation')
      end

      def cardinal_azimuth
        fetch('compass.cardinal.azimuth')
      end

      def ordinal_azimuth
        fetch('compass.ordinal.azimuth')
      end

      def half_wind_azimuth
        fetch('compass.half-wind.azimuth')
      end

      def quarter_wind_azimuth
        fetch('compass.quarter-wind.azimuth')
      end
    end
  end
end
