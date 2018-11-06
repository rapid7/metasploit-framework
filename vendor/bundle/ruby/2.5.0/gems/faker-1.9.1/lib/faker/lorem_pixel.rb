module Faker
  class LoremPixel < Base
    class << self
      SUPPORTED_CATEGORIES = %w[abstract
                                animals
                                business
                                cats
                                city
                                food
                                nightlife
                                fashion
                                people
                                nature
                                sports
                                technics
                                transport].freeze

      # rubocop:disable Metrics/ParameterLists
      def image(size = '300x300', is_gray = false, category = nil, number = nil, text = nil, secure: true)
        raise ArgumentError, 'Size should be specified in format 300x300' unless size =~ /^[0-9]+x[0-9]+$/
        raise ArgumentError, "Supported categories are #{SUPPORTED_CATEGORIES.join(', ')}" unless category.nil? || SUPPORTED_CATEGORIES.include?(category)
        raise ArgumentError, 'Category required when number is passed' if !number.nil? && category.nil?
        raise ArgumentError, 'Number must be between 1 and 10' unless number.nil? || (1..10).cover?(number)
        raise ArgumentError, 'Category and number must be passed when text is passed' if !text.nil? && number.nil? && category.nil?

        url_parts = secure ? ['https:/'] : ['http:/']
        url_parts << ['lorempixel.com']
        url_parts << 'g' if is_gray
        url_parts += size.split('x')
        url_parts += [category, number, text].compact
        url_parts.join('/')
      end
      # rubocop:enable Metrics/ParameterLists
    end
  end
end
