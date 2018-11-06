module Faker
  class Esport < Base
    class << self
      def player
        fetch('esport.players')
      end

      def team
        fetch('esport.teams')
      end

      def league
        fetch('esport.leagues')
      end

      def event
        fetch('esport.events')
      end

      def game
        fetch('esport.games')
      end
    end
  end
end
