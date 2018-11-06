module Faker
  class Yoda < Base
    class << self
      # from: http://morecoolquotes.com/famous-yoda-quotes/
      def quote
        fetch('yoda.quotes')
      end
    end
  end
end
