require 'rack/utils'

module Msf::WebServices::Authentication
  module Strategies
    class ApiToken < Warden::Strategies::Base
      AUTHORIZATION = 'HTTP_AUTHORIZATION'
      AUTHORIZATION_SCHEME = 'Bearer'
      AUTHORIZATION_PATTERN = /\A#{AUTHORIZATION_SCHEME}\s+(?<token>\S.*)\z/.freeze

      # Check if request contains valid data and should be authenticated.
      # @return [Boolean] true if strategy should be run for the request; otherwise, false.
      def valid?
        # Run the strategy so that #authenticate! can grant the bootstrap exemption.
        return true unless auth_initialized?

        !bearer_token.nil?
      end

      # Authenticate the request.
      def authenticate!
        unless auth_initialized?
          return success!({ message: 'Initialize authentication by creating an initial user account.' })
        end

        token = bearer_token
        throw(:warden, message: 'Invalid API token.', code: 401) if blank_token?(token)

        request.env['msf.api_token'].nil? ? auth_from_db(token) : auth_from_env(token)
      end

      # Whether the application has completed authentication bootstrapping.
      #
      # An application opts into the unauthenticated bootstrap flow - which allows an
      # initial user account to be created before any credentials exist - by explicitly
      # setting 'msf.auth_initialized' to false. Any other value, including the key
      # being absent, requires authentication so that the strategy fails closed for
      # applications that never advertise this state.
      #
      # @return [Boolean] true if authentication must be enforced; otherwise, false.
      def auth_initialized?
        request.env['msf.auth_initialized'] != false
      end

      # The token carried by an Authorization header using the Bearer scheme. Tokens are
      # only accepted here, never from the query string, so that they stay out of access logs.
      #
      # @return [String, nil] the token, or nil if the header is absent, uses a different
      #   scheme, or carries no token.
      def bearer_token
        authorization = request.env[AUTHORIZATION]
        return unless authorization.is_a?(String)

        AUTHORIZATION_PATTERN.match(authorization)&.[](:token)
      end

      # Authenticates the user associated with the API token from the DB
      def auth_from_db(token)
        db_manager = env['msf.db_manager']

        # Reached when the application was never able to establish a database
        # connection. Reject rather than raising a 500 from a nil db_manager.
        throw(:warden, message: 'Authentication is not configured.', code: 401) if db_manager.nil?
        throw(:warden, message: 'Invalid API token.', code: 401) if blank_token?(token)

        user = db_manager.users(persistence_token: token).first

        validation_data = validate_user(user)
        if validation_data[:valid]
          success!(user)
        else
          throw(:warden, message: validation_data[:message], code: validation_data[:code])
        end
      end

      # Validates the user associated with the API token.
      #
      # @return [Hash] User validation data
      # @option :valid [Boolean] True if the user is valid; otherwise, false.
      # @option :code [Integer] 0 if the user is valid; otherwise, a non-zero strategy failure code.
      # @option :message [String] strategy failure message
      def validate_user(user)
        !user.nil? ? {valid: true, code: 0, message: nil} : {valid: false, code: 401, message: "Invalid API token."}
      end

      # Authenticates the API token from an environment variable
      def auth_from_env(token)
        expected_token = request.env['msf.api_token']

        # Compared in constant time to avoid leaking the token a byte at a time.
        if !blank_token?(token) && !blank_token?(expected_token) && Rack::Utils.secure_compare(token, expected_token)
          success!(message: "Successful auth from token")
        else
          throw(:warden, message: 'Invalid API token.', code: 401)
        end
      end

      # @return [Boolean] true if the token is missing or contains no usable characters.
      def blank_token?(token)
        !token.is_a?(String) || token.strip.empty?
      end
    end
  end
end
