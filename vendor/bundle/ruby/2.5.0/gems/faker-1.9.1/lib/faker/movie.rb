module Faker
  class Movie < Base
    class << self
      def quote
        fetch('movie.quote')
      end
    end
  end
end
