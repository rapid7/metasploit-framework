module Faker
  class Seinfeld < Base
    class << self
      def character
        fetch('seinfeld.character')
      end

      def quote
        fetch('seinfeld.quote')
      end
    end
  end
end
