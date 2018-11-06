module Faker
  class Football < Base
    class << self
      def team
        fetch('football.teams')
      end

      def player
        fetch('football.players')
      end

      def coach
        fetch('football.coaches')
      end

      def competition
        fetch('football.competitions')
      end
    end
  end
end
