module Faker
  class Nation < Base
    flexible :nation
    class << self
      def nationality
        fetch('nation.nationality')
      end

      def language
        fetch('nation.language')
      end

      # Fetch random capital city
      def capital_city
        fetch('nation.capital_city')
      end

      # Fetch random natinal sport
      def national_sport
        fetch('team.sport')
      end
    end
  end
end
