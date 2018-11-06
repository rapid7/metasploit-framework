module Faker
  class Military < Base
    class << self
      def army_rank
        fetch('military.army_rank')
      end

      def marines_rank
        fetch('military.marines_rank')
      end

      def navy_rank
        fetch('military.navy_rank')
      end

      def air_force_rank
        fetch('military.air_force_rank')
      end

      def dod_paygrade
        fetch('military.dod_paygrade')
      end
    end
  end
end
