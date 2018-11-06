module Faker
  class SwordArtOnline < Base
    class << self
      def real_name
        fetch('sword_art_online.real_name')
      end

      def game_name
        fetch('sword_art_online.game_name')
      end

      def location
        fetch('sword_art_online.location')
      end

      def item
        fetch('sword_art_online.item')
      end
    end
  end
end
