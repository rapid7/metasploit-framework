module Faker
  class Team < Base
    flexible :team

    class << self
      def name
        parse('team.name')
      end

      def creature
        fetch('team.creature')
      end

      def state
        fetch('address.state')
      end

      def sport
        fetch('team.sport')
      end

      def mascot
        fetch('team.mascot')
      end
    end
  end
end
