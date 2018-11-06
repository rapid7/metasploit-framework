module Faker
  class OnePiece < Base
    class << self
      def character
        fetch('one_piece.characters')
      end

      def sea
        fetch('one_piece.seas')
      end

      def island
        fetch('one_piece.islands')
      end

      def location
        fetch('one_piece.locations')
      end

      def quote
        fetch('one_piece.quotes')
      end

      def akuma_no_mi
        fetch('one_piece.akumas_no_mi')
      end
    end
  end
end
