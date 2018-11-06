module Faker
  class FunnyName < Base
    flexible :funny_name

    class << self
      def name
        fetch('funny_name.name')
      end

      def two_word_name
        two_word_names = fetch_all('funny_name.name').select do |name|
          name.count(' ') == 1
        end

        sample(two_word_names)
      end

      def three_word_name
        three_word_names = fetch_all('funny_name.name').select do |name|
          name.count(' ') == 2
        end

        sample(three_word_names)
      end

      def four_word_name
        four_word_names = fetch_all('funny_name.name').select do |name|
          name.count(' ') == 3
        end

        sample(four_word_names)
      end

      def name_with_initial
        names_with_initials = fetch_all('funny_name.name').select do |name|
          name.count('.') > 0
        end

        sample(names_with_initials)
      end
    end
  end
end
