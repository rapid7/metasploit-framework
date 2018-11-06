module Faker
  class Fallout < Base
    class << self
      def character
        fetch('fallout.characters')
      end

      def faction
        fetch('fallout.factions')
      end

      def location
        fetch('fallout.locations')
      end

      def quote
        fetch('fallout.quotes')
      end
    end
  end
end
