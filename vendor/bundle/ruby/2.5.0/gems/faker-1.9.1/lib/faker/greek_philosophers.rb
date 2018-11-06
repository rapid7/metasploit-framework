module Faker
  class GreekPhilosophers < Base
    class << self
      def name
        fetch('greek_philosophers.names')
      end

      def quote
        fetch('greek_philosophers.quotes')
      end
    end
  end
end
