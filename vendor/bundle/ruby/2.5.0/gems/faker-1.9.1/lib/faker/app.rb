module Faker
  class App < Base
    class << self
      def name
        fetch('app.name')
      end

      def version
        parse('app.version')
      end

      def author
        parse('app.author')
      end

      def semantic_version(major: 0..9, minor: 0..9, patch: 1..9)
        [major, minor, patch].map { |chunk| sample(Array(chunk)) }.join('.')
      end
    end
  end
end
