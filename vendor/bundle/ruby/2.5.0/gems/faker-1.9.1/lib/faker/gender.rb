module Faker
  class Gender < Base
    class << self
      def type
        fetch('gender.types')
      end

      def binary_type
        fetch('gender.binary_types')
      end
    end
  end
end
