module Faker
  class Friends < Base
    class << self
      def character
        fetch('friends.characters')
      end

      def location
        fetch('friends.locations')
      end

      def quote
        fetch('friends.quotes')
      end
    end
  end
end
