module Faker
  class ProgrammingLanguage < Base
    class << self
      def name
        fetch('programming_language.name')
      end

      def creator
        fetch('programming_language.creator')
      end
    end
  end
end
