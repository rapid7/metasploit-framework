module Faker
  class DragonBall < Base
    class << self
      def character
        fetch('dragon_ball.characters')
      end
    end
  end
end
