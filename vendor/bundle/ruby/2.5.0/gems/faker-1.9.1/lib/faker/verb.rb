module Faker
  class Verb < Base
    class << self
      def base
        fetch('verbs.base')
      end

      def past
        fetch('verbs.past')
      end

      def past_participle
        fetch('verbs.past_participle')
      end

      def simple_present
        fetch('verbs.simple_present')
      end

      def ing_form
        fetch('verbs.ing_form')
      end
    end
  end
end
