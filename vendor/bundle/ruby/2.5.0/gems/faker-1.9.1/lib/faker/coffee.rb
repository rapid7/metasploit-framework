module Faker
  class Coffee < Base
    class << self
      def blend_name
        parse('coffee.blend_name')
      end

      def origin
        country = fetch('coffee.country')
        region = fetch("coffee.regions.#{search_format(country)}")
        "#{region}, #{country}"
      end

      def variety
        fetch('coffee.variety')
      end

      def notes
        parse('coffee.notes')
      end

      def intensifier
        fetch('coffee.intensifier')
      end

      private

      def search_format(key)
        key.split.length > 1 ? key.split.join('_').downcase : key.downcase
      end
    end
  end
end
