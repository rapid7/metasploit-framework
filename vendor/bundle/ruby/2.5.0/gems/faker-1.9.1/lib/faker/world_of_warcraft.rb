module Faker
  class WorldOfWarcraft < Base
    class << self
      def hero
        fetch('world_of_warcraft.hero')
      end

      def quote
        fetch('world_of_warcraft.quotes')
      end
    end
  end
end
