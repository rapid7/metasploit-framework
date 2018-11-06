module Faker
  class PrincessBride < Base
    class << self
      def character
        fetch('princess_bride.characters')
      end

      def quote
        fetch('princess_bride.quotes')
      end
    end
  end
end
