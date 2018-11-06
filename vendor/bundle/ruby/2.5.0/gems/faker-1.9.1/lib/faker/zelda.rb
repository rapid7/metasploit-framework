module Faker
  class Zelda < Base
    flexible :space
    class << self
      def game
        fetch('zelda.games')
      end

      def character
        fetch('zelda.characters')
      end

      def location
        fetch('zelda.locations')
      end

      def item
        fetch('zelda.items')
      end
    end
  end
end
