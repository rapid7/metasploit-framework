module Faker
  class Dog < Base
    flexible :dog

    class << self
      def name
        fetch('dog.name')
      end

      def breed
        fetch('dog.breed')
      end

      def sound
        fetch('dog.sound')
      end

      def meme_phrase
        fetch('dog.meme_phrase')
      end

      def age
        fetch('dog.age')
      end

      def gender
        fetch('dog.gender')
      end

      def coat_length
        fetch('dog.coat_length')
      end

      def size
        fetch('dog.size')
      end
    end
  end
end
