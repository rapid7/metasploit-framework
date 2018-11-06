module Faker
  class Ancient < Base
    class << self
      def god
        fetch('ancient.god')
      end

      def primordial
        fetch('ancient.primordial')
      end

      def titan
        fetch('ancient.titan')
      end

      def hero
        fetch('ancient.hero')
      end
    end
  end
end
