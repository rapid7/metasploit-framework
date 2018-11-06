module Faker
  class Music < Base
    class << self
      def key
        sample(keys) + sample(key_variants)
      end

      def chord
        key + sample(chord_types)
      end

      def instrument
        fetch('music.instruments')
      end

      def keys
        %w[C D E F G A B]
      end

      def key_variants
        ['b', '#', '']
      end

      def key_types
        ['', 'm']
      end

      def chord_types
        ['', 'maj', '6', 'maj7', 'm', 'm7', '-7', '7', 'dom7', 'dim', 'dim7', 'm7b5']
      end

      def band
        fetch('music.bands')
      end

      def album
        fetch('music.albums')
      end

      def genre
        fetch('music.genres')
      end
    end
  end
end
