module Faker
  class DumbAndDumber < Base
    class << self
      def actor
        fetch('dumb_and_dumber.actors')
      end

      def character
        fetch('dumb_and_dumber.characters')
      end

      def quote
        fetch('dumb_and_dumber.quotes')
      end
    end
  end
end
