module Faker
  class LordOfTheRings < Base
    class << self
      def character
        fetch('lord_of_the_rings.characters')
      end

      def location
        fetch('lord_of_the_rings.locations')
      end

      def quote
        fetch('lord_of_the_rings.quotes')
      end
    end
  end
end
