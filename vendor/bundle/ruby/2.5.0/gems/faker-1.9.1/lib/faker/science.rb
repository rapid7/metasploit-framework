module Faker
  class Science < Base
    class << self
      def element
        fetch('science.element')
      end

      def element_symbol
        fetch('science.element_symbol')
      end

      def scientist
        fetch('science.scientist')
      end
    end
  end
end
