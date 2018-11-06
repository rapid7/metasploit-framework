module Faker
  class BossaNova < Base
    class << self
      def artist
        fetch('bossa_nova.artists')
      end

      def song
        fetch('bossa_nova.songs')
      end
    end
  end
end
