module Faker
  class Community < Base
    class << self
      def characters
        fetch('community.characters')
      end

      def quotes
        fetch('community.quotes')
      end
    end
  end
end
