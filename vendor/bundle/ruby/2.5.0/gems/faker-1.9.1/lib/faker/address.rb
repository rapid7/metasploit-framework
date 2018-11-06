module Faker
  class Address < Base
    flexible :address

    class << self
      def city(options = {})
        parse(options[:with_state] ? 'address.city_with_state' : 'address.city')
      end

      def street_name
        parse('address.street_name')
      end

      def street_address(include_secondary = false)
        numerify(parse('address.street_address') + (include_secondary ? ' ' + secondary_address : ''))
      end

      def secondary_address
        bothify(fetch('address.secondary_address'))
      end

      def building_number
        bothify(fetch('address.building_number'))
      end

      def community
        parse('address.community')
      end

      def zip_code(state_abbreviation = '')
        if state_abbreviation.empty?
          letterified_string = letterify(fetch('address.postcode'))
          return numerify(letterified_string, leading_zero: true)
        end

        # provide a zip code that is valid for the state provided
        # see http://www.fincen.gov/forms/files/us_state_territory_zip_codes.pdf
        bothify(fetch('address.postcode_by_state.' + state_abbreviation))
      end

      def time_zone
        fetch('address.time_zone')
      end

      alias zip zip_code
      alias postcode zip_code

      def street_suffix
        fetch('address.street_suffix')
      end

      def city_suffix
        fetch('address.city_suffix')
      end

      def city_prefix
        fetch('address.city_prefix')
      end

      def state_abbr
        fetch('address.state_abbr')
      end

      def state
        fetch('address.state')
      end

      def country
        fetch('address.country')
      end

      def country_code
        fetch('address.country_code')
      end

      def country_code_long
        fetch('address.country_code_long')
      end

      def latitude
        ((rand * 180) - 90).to_f
      end

      def longitude
        ((rand * 360) - 180).to_f
      end

      def full_address
        parse('address.full_address')
      end
    end
  end
end
