module Faker
  class GameOfThrones < Base
    class << self
      def character
        fetch('game_of_thrones.characters')
      end

      def house
        fetch('game_of_thrones.houses')
      end

      def city
        fetch('game_of_thrones.cities')
      end

      def quote
        fetch('game_of_thrones.quotes')
      end

      def dragon
        fetch('game_of_thrones.dragons')
      end
    end
  end
end
