module Faker
  class Dessert < Base
    flexible :dessert

    class << self
      def variety
        fetch('dessert.variety')
      end

      def topping
        fetch('dessert.topping')
      end

      def flavor
        fetch('dessert.flavor')
      end
    end
  end
end
