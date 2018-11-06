module Faker
  class Shakespeare < Base
    class << self
      def hamlet_quote
        sample(hamlet)
      end

      def as_you_like_it_quote
        sample(as_you_like_it)
      end

      def king_richard_iii_quote
        sample(king_richard_iii)
      end

      def romeo_and_juliet_quote
        sample(romeo_and_juliet)
      end

      def hamlet
        fetch('shakespeare.hamlet')
      end

      def as_you_like_it
        fetch('shakespeare.as_you_like_it')
      end

      def king_richard_iii
        fetch('shakespeare.king_richard_iii')
      end

      def romeo_and_juliet
        fetch('shakespeare.romeo_and_juliet')
      end
    end
  end
end
