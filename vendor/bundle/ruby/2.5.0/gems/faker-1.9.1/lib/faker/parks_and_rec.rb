module Faker
  class ParksAndRec < Base
    class << self
      def character
        fetch('parks_and_rec.characters')
      end

      def city
        fetch('parks_and_rec.cities')
      end
    end
  end
end
