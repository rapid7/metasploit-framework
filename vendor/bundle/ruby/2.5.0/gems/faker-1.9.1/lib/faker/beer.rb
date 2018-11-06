module Faker
  class Beer < Base
    flexible :beer

    class << self
      def name
        fetch('beer.name')
      end

      def style
        fetch('beer.style')
      end

      def hop
        fetch('beer.hop')
      end

      def yeast
        fetch('beer.yeast')
      end

      def malts
        fetch('beer.malt')
      end

      def ibu
        rand(10..100).to_s + ' IBU'
      end

      def alcohol
        rand(2.0..10.0).round(1).to_s + '%'
      end

      def blg
        rand(5.0..20.0).round(1).to_s + '°Blg'
      end
    end
  end
end
