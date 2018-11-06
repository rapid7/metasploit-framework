module Faker
  class Dota < Base
    class << self
      def hero
        fetch('dota.hero')
      end

      def item
        fetch('dota.item')
      end

      def team
        fetch('dota.team')
      end

      def player
        fetch('dota.player')
      end

      def quote(hero = 'abaddon')
        fetch("dota.#{hero}.quote")
      end
    end
  end
end
