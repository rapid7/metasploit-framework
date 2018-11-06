module Faker
  class Boolean < Base
    class << self
      def boolean(true_ratio = 0.5)
        (rand < true_ratio)
      end
    end
  end
end
