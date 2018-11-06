module Faker
  class Color < Base
    class << self
      def hex_color
        format('#%06x', (rand * 0xffffff))
      end

      def color_name
        fetch('color.name')
      end

      def single_rgb_color
        sample((0..255).to_a)
      end

      def rgb_color
        Array.new(3) { single_rgb_color }
      end

      # returns [hue, saturation, lightness]
      def hsl_color
        [sample((0..360).to_a), rand.round(2), rand.round(2)]
      end

      def hsla_color
        hsl_color << rand.round(1)
      end
    end
  end
end
