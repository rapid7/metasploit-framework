module Faker
  class Matz < Base
    class << self
      def quote
        fetch('matz.quotes')
      end
    end
  end
end
