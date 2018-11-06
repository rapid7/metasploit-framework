module Faker
  class BojackHorseman < Base
    class << self
      def character
        fetch('bojack_horseman.characters')
      end

      def tongue_twister
        fetch('bojack_horseman.tongue_twisters')
      end

      def quote
        fetch('bojack_horseman.quotes')
      end
    end
  end
end
