module Faker
  class Types < Base
    CHARACTERS = ('0'..'9').to_a + ('a'..'z').to_a
    SIMPLE_TYPES = %i[string fixnum].freeze
    COMPLEX_TYPES = %i[hash array].freeze

    class << self
      def rb_string(words = 1)
        resolved_num = resolve(words)
        word_list =
          translate('faker.lorem.words')

        word_list *= ((resolved_num / word_list.length) + 1)
        shuffle(word_list)[0, resolved_num].join(' ')
      end

      def character
        sample(CHARACTERS)
      end

      def rb_integer(from = 0, to = 100)
        rand(from..to).to_i
      end

      def rb_hash(key_count = 1)
        {}.tap do |hsh|
          Lorem.words(key_count * 2).uniq.first(key_count).each do |s|
            hsh.merge!(s.to_sym => random_type)
          end
        end
      end

      def complex_rb_hash(key_count = 1)
        {}.tap do |hsh|
          Lorem.words(key_count * 2).uniq.first(key_count).each do |s|
            hsh.merge!(s.to_sym => random_complex_type)
          end
        end
      end

      def rb_array(len = 1)
        [].tap do |ar|
          len.times do
            ar.push random_type
          end
        end
      end

      def random_type
        type_to_use = SIMPLE_TYPES[rand(0..SIMPLE_TYPES.length - 1)]
        case type_to_use
        when :string
          rb_string
        when :fixnum
          rb_integer
        end
      end

      def random_complex_type
        types = SIMPLE_TYPES + COMPLEX_TYPES
        type_to_use = types[rand(0..types.length - 1)]
        case type_to_use
        when :string
          rb_string
        when :fixnum
          rb_integer
        when :hash
          rb_hash
        when :array
          rb_array
        end
      end

      private

      def titleize(word)
        word.split(/(\W)/).map(&:capitalize).join
      end

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
