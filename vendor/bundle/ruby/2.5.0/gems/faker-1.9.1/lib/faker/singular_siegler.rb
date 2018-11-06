module Faker
  class SingularSiegler < Base
    class << self
      def quote
        fetch('singular_siegler.quotes')
      end
    end
  end
end
