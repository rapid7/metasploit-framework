module Faker
  class Stargate < Base
    class << self
      def character
        fetch('stargate.characters')
      end

      def planet
        fetch('stargate.planets')
      end

      def quote
        fetch('stargate.quotes')
      end
    end
  end
end
