module Faker
  class Appliance < Base
    class << self
      def brand
        fetch('appliance.brand')
      end

      def equipment
        fetch('appliance.equipment')
      end
    end
  end
end
