module Faker
  class Overwatch < Base
    class << self
      def hero
        fetch('overwatch.heroes')
      end

      def location
        fetch('overwatch.locations')
      end

      def quote
        fetch('overwatch.quotes')
      end
    end
  end
end
