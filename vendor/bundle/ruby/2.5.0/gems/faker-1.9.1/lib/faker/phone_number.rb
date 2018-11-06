module Faker
  class PhoneNumber < Base
    class << self
      def phone_number
        parse('phone_number.formats')
      end

      def cell_phone
        parse('cell_phone.formats')
      end

      # US and Canada only
      def area_code
        fetch('phone_number.area_code')
      rescue I18n::MissingTranslationData
        nil
      end

      # US and Canada only
      def exchange_code
        fetch('phone_number.exchange_code')
      rescue I18n::MissingTranslationData
        nil
      end

      # US and Canada only
      # Can be used for both extensions and last four digits of phone number.
      # Since extensions can be of variable length, this method taks a length parameter
      def subscriber_number(length = 4)
        rand.to_s[2..(1 + length)]
      end

      alias extension subscriber_number
    end
  end
end
