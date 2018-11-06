module Faker
  class Dune < Base
    class << self
      # QUOTED_CHARACTERS = fetch("dune.quotes")
      # SAYING_SOURCES = %w(translate("faker.dune.sources"))

      def character
        fetch('dune.characters')
      end

      def title
        fetch('dune.titles')
      end

      def planet
        fetch('dune.planets')
      end

      def quote(character = nil)
        quoted_characters = translate('faker.dune.quotes').keys

        if character.nil?
          character = sample(quoted_characters).to_s
        else
          character.to_s.downcase!

          unless quoted_characters.include?(character.to_sym)
            raise ArgumentError,
                  "Characters quoted can be left blank or #{quoted_characters.join(', ')}"
          end
        end

        fetch('dune.quotes.' + character)
      end

      def saying(source = nil)
        sourced_sayings = translate('faker.dune.sayings').keys

        if source.nil?
          source = sample(sourced_sayings).to_s
        else
          source.to_s.downcase!

          unless sourced_sayings.include?(source.to_sym)
            raise ArgumentError,
                  "Sources quoted in sayings can be left blank or #{sourced_sayings.join(', ')}"
          end
        end

        fetch('dune.sayings.' + source)
      end
    end
  end
end
