module Faker
  class Currency < Base
    class << self
      def name
        fetch('currency.name')
      end

      def code
        fetch('currency.code')
      end

      def symbol
        fetch('currency.symbol')
      end
    end
  end
end
