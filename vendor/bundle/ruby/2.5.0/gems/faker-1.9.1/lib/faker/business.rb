require 'date'

module Faker
  class Business < Base
    flexible :business

    class << self
      def credit_card_number
        fetch('business.credit_card_numbers')
      end

      def credit_card_expiry_date
        ::Date.today + (365 * rand(1..4))
      end

      def credit_card_type
        fetch('business.credit_card_types')
      end
    end
  end
end
