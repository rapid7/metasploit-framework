module Faker
  class Placeholdit < Base
    class << self
      SUPPORTED_FORMATS = %w[png jpg gif jpeg].freeze

      def image(size = '300x300', format = 'png', background_color = nil, text_color = nil, text = nil)
        background_color = generate_color if background_color == :random
        text_color = generate_color if text_color == :random

        raise ArgumentError, 'Size should be specified in format 300x300' unless size =~ /^[0-9]+x[0-9]+$/
        raise ArgumentError, "Supported formats are #{SUPPORTED_FORMATS.join(', ')}" unless SUPPORTED_FORMATS.include?(format)
        raise ArgumentError, "background_color must be a hex value without '#'" unless background_color.nil? || background_color.match(/((?:^\h{3}$)|(?:^\h{6}$)){1}(?!.*\H)/)
        raise ArgumentError, "text_color must be a hex value without '#'" unless text_color.nil? || text_color.match(/((?:^\h{3}$)|(?:^\h{6}$)){1}(?!.*\H)/)

        image_url = "https://placehold.it/#{size}.#{format}"
        image_url += "/#{background_color}" if background_color
        image_url += "/#{text_color}" if text_color
        image_url += "?text=#{text}" if text
        image_url
      end

      private

      def generate_color
        format('%06x', (rand * 0xffffff))
      end
    end
  end
end
