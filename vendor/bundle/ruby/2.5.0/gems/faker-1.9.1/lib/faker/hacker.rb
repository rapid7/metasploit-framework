# Port of http://shinytoylabs.com/jargon/
module Faker
  class Hacker < Base
    flexible :hacker

    class << self
      def say_something_smart
        sample(phrases)
      end

      def abbreviation
        fetch('hacker.abbreviation')
      end

      def adjective
        fetch('hacker.adjective')
      end

      def noun
        fetch('hacker.noun')
      end

      def verb
        fetch('hacker.verb')
      end

      def ingverb
        fetch('hacker.ingverb')
      end

      def phrases
        ["If we #{verb} the #{noun}, we can get to the #{abbreviation} #{noun} through the #{adjective} #{abbreviation} #{noun}!",
         "We need to #{verb} the #{adjective} #{abbreviation} #{noun}!",
         "Try to #{verb} the #{abbreviation} #{noun}, maybe it will #{verb} the #{adjective} #{noun}!",
         "You can't #{verb} the #{noun} without #{ingverb} the #{adjective} #{abbreviation} #{noun}!",
         "Use the #{adjective} #{abbreviation} #{noun}, then you can #{verb} the #{adjective} #{noun}!",
         "The #{abbreviation} #{noun} is down, #{verb} the #{adjective} #{noun} so we can #{verb} the #{abbreviation} #{noun}!",
         "#{ingverb} the #{noun} won't do anything, we need to #{verb} the #{adjective} #{abbreviation} #{noun}!".capitalize,
         "I'll #{verb} the #{adjective} #{abbreviation} #{noun}, that should #{noun} the #{abbreviation} #{noun}!"]
      end
    end
  end
end
