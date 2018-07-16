module Authentication
  module Strategies
    class ApiToken < Warden::Strategies::Base
      AUTHORIZATION = 'HTTP_AUTHORIZATION'
      AUTHORIZATION_SCHEME = 'Bearer'
      TOKEN_QUERY_PARAM = 'token'

      # Check if request contains valid data and should be authenticated.
      # @return [Boolean] true if strategy should be run for the request; otherwise, false.
      def valid?
        auth_initialized = request.env['AuthInitialized']
        authorization = request.env[AUTHORIZATION]
        !auth_initialized || (authorization.is_a?(String) && authorization.start_with?(AUTHORIZATION_SCHEME)) || !params[TOKEN_QUERY_PARAM].nil?
      end

      # Authenticate the request.
      def authenticate!
        auth_initialized = request.env['AuthInitialized']
        db_manager = env['DBManager']
        authorization = request.env[AUTHORIZATION]
        if !auth_initialized
          success!({message: "Initialize authentication by creating an initial user account."})
        else
          if authorization.is_a?(String) && authorization.start_with?(AUTHORIZATION_SCHEME)
            token = authorization.sub(/^#{AUTHORIZATION_SCHEME}\s+/, '')
          else
            token = params[TOKEN_QUERY_PARAM]
          end

          user = db_manager.users(persistence_token: token).first

          if valid_user?(user)
            success!(user)
          else
            throw(:warden, message: strategy_failure_message)
          end
        end
      end

      # Validates the user associated with the API token.
      #
      # @return [Boolean] True if the user is valid; otherwise, false.
      def valid_user?(user)
        !user.nil?
      end

      # Gets the strategy failure message.
      #
      # @return [String] The strategy failure message.
      def strategy_failure_message
        "Invalid API token."
      end

    end
  end
end
