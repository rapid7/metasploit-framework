module Faker
  class TheITCrowd < Base
    class << self
      def actor
        fetch('the_it_crowd.actors')
      end

      def character
        fetch('the_it_crowd.characters')
      end

      def email
        fetch('the_it_crowd.emails')
      end

      def quote
        fetch('the_it_crowd.quotes')
      end
    end
  end
end
