module Authentication
  module Strategies
    class AdminApiToken < ApiToken

      # Validates the user associated with the API token is an admin.
      #
      # @return [Boolean] True if the user is valid; otherwise, false.
      def valid_user?(user)
        super && user.admin
      end

      # Gets the strategy failure message.
      #
      # @return [String] The strategy failure message.
      def strategy_failure_message
        "Invalid permissions."
      end

    end
  end
end
