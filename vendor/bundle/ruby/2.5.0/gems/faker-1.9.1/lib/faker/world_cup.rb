module Faker
  class WorldCup < Base
    class << self
      def team
        fetch('world_cup.teams')
      end

      def city
        fetch('world_cup.cities')
      end

      def stadium
        fetch('world_cup.stadiums')
      end

      def group(group = 'group_A')
        fetch("world_cup.groups.#{group}")
      end

      def roster(country = 'Egypt', type = 'coach')
        fetch("world_cup.rosters.#{country}.#{type}")
      end
    end
  end
end
