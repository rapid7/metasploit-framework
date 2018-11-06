module Faker
  class RockBand < Base
    class << self
      def name
        fetch('rock_band.name')
      end
    end
  end
end
