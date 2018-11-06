module Faker
  class RickAndMorty < Base
    class << self
      def character
        fetch('rick_and_morty.characters')
      end

      def location
        fetch('rick_and_morty.locations')
      end

      def quote
        fetch('rick_and_morty.quotes')
      end
    end
  end
end
