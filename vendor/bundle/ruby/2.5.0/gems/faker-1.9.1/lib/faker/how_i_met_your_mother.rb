module Faker
  class HowIMetYourMother < Base
    class << self
      def character
        fetch('how_i_met_your_mother.character')
      end

      def catch_phrase
        fetch('how_i_met_your_mother.catch_phrase')
      end

      def high_five
        fetch('how_i_met_your_mother.high_five')
      end

      def quote
        fetch('how_i_met_your_mother.quote')
      end
    end
  end
end
