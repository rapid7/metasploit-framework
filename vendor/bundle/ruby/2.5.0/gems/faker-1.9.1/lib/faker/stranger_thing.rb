module Faker
  class StrangerThings < Base
    class << self
      def quote
        fetch('stranger_things.quote')
      end

      def character
        fetch('stranger_things.character')
      end
    end
  end
end
