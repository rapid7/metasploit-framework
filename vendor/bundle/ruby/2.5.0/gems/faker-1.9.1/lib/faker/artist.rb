module Faker
  class Artist < Base
    class << self
      def name
        fetch('artist.names')
      end
    end
  end
end
