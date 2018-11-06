module Faker
  class Superhero < Base
    class << self
      def power
        fetch('superhero.power')
      end

      def prefix
        fetch('superhero.prefix')
      end

      def suffix
        fetch('superhero.suffix')
      end

      def descriptor
        fetch('superhero.descriptor')
      end

      def name
        parse('superhero.name')
      end
    end
  end
end
