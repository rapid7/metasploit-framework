module Faker
  class Hobbit < Base
    class << self
      def character
        fetch('hobbit.character')
      end

      def thorins_company
        fetch('hobbit.thorins_company')
      end

      def quote
        fetch('hobbit.quote')
      end

      def location
        fetch('hobbit.location')
      end
    end
  end
end
