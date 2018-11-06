module Faker
  class ElderScrolls < Base
    class << self
      def race
        fetch('elder_scrolls.race')
      end

      def city
        fetch('elder_scrolls.city')
      end

      def creature
        fetch('elder_scrolls.creature')
      end

      def region
        fetch('elder_scrolls.region')
      end

      def dragon
        fetch('elder_scrolls.dragon')
      end

      def name
        "#{fetch('elder_scrolls.first_name')} #{fetch('elder_scrolls.last_name')}"
      end

      def first_name
        fetch('elder_scrolls.first_name')
      end

      def last_name
        fetch('elder_scrolls.last_name')
      end
    end
  end
end
