module Faker
  class Pokemon < Base
    class << self
      def name
        fetch('pokemon.names')
      end

      def location
        fetch('pokemon.locations')
      end

      def move
        fetch('pokemon.moves')
      end
    end
  end
end
