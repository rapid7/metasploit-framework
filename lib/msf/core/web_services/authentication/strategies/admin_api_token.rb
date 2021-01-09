module Msf::WebServices::Authentication
  module Strategies
    class AdminApiToken < ApiToken

      # Validates the user associated with the API token is an admin.
      #
      # @return [Hash] User validation data
      # @option :valid [Boolean] True if the user is valid; otherwise, false.
      # @option :code [Integer] 0 if the user is valid; otherwise, a non-zero strategy failure code.
      # @option :message [String] strategy failure message
      def validate_user(user)
        # perform parent validation first
        data = super
        return data if !data[:valid]

        user.admin ? {valid: true, code: 0, message: nil} : {valid: false, code: 403, message: "Invalid permissions."}
      end

    end
  end
end
