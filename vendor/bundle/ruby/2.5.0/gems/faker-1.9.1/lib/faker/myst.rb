module Faker
  class Myst < Base
    class << self
      def game
        fetch('myst.games')
      end

      def creature
        fetch('myst.creatures')
      end

      def age
        fetch('myst.ages')
      end

      def character
        fetch('myst.characters')
      end

      def quote
        fetch('myst.quotes')
      end
    end
  end
end
