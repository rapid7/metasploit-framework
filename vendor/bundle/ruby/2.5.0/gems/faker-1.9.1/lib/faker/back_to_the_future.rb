module Faker
  class BackToTheFuture < Base
    class << self
      def character
        fetch('back_to_the_future.characters')
      end

      def date
        fetch('back_to_the_future.dates')
      end

      def quote
        fetch('back_to_the_future.quotes')
      end
    end
  end
end
