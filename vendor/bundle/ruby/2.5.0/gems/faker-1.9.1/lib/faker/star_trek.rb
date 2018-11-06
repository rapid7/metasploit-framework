module Faker
  class StarTrek < Base
    class << self
      def character
        fetch('star_trek.character')
      end

      def location
        fetch('star_trek.location')
      end

      def specie
        fetch('star_trek.specie')
      end

      def villain
        fetch('star_trek.villain')
      end
    end
  end
end
