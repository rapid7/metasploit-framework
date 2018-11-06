module Faker
  class Lovecraft < Base
    class << self
      def location
        fetch('lovecraft.location')
      end

      def fhtagn(number_of = 1)
        Array.new(number_of) { fetch('lovecraft.fhtagn') }.join('. ')
      end

      def deity
        fetch('lovecraft.deity')
      end

      def tome
        fetch('lovecraft.tome')
      end

      def sentence(word_count = 4, random_words_to_add = 6)
        words(word_count + rand(random_words_to_add.to_i).to_i, true).join(' ').capitalize + '.'
      end

      def word
        random_word = sample(translate('faker.lovecraft.words'))
        random_word =~ /\s/ ? word : random_word
      end

      def words(num = 3, spaces_allowed = false)
        resolved_num = resolve(num)
        word_list = translate('faker.lovecraft.words')
        word_list *= ((resolved_num / word_list.length) + 1)

        return shuffle(word_list)[0, resolved_num] if spaces_allowed
        words = shuffle(word_list)[0, resolved_num]
        words.each_with_index { |w, i| words[i] = word if w =~ /\s/ }
      end

      def sentences(sentence_count = 3)
        [].tap do |sentences|
          1.upto(resolve(sentence_count)) do
            sentences << sentence(3)
          end
        end
      end

      def paragraph(sentence_count = 3, random_sentences_to_add = 3)
        sentences(resolve(sentence_count) + rand(random_sentences_to_add.to_i).to_i).join(' ')
      end

      def paragraphs(paragraph_count = 3)
        [].tap do |paragraphs|
          1.upto(resolve(paragraph_count)) do
            paragraphs << paragraph(3)
          end
        end
      end

      def paragraph_by_chars(chars = 256)
        paragraph = paragraph(3)

        paragraph += ' ' + paragraph(3) while paragraph.length < chars

        paragraph[0...chars - 1] + '.'
      end

      private

      # If an array or range is passed, a random value will be selected.
      # All other values are simply returned.
      def resolve(value)
        case value
        when Array then sample(value)
        when Range then rand value
        else value
        end
      end
    end
  end
end
