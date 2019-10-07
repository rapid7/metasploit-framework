module Authentication
  module Strategies
    class ApiToken < Warden::Strategies::Base
      AUTHORIZATION = 'HTTP_AUTHORIZATION'
      AUTHORIZATION_SCHEME = 'Bearer'
      TOKEN_QUERY_PARAM = 'token'

      # Check if request contains valid data and should be authenticated.
      # @return [Boolean] true if strategy should be run for the request; otherwise, false.
      def valid?
        auth_initialized = request.env['msf.auth_initialized']
        authorization = request.env[AUTHORIZATION]
        !auth_initialized || (authorization.is_a?(String) && authorization.start_with?(AUTHORIZATION_SCHEME)) || !params[TOKEN_QUERY_PARAM].nil?
      end

      # Authenticate the request.
      def authenticate!
        auth_initialized = request.env['msf.auth_initialized']
        authorization = request.env[AUTHORIZATION]
        if !auth_initialized
          success!({message: "Initialize authentication by creating an initial user account."})
        else
          if authorization.is_a?(String) && authorization.start_with?(AUTHORIZATION_SCHEME)
            token = authorization.sub(/^#{AUTHORIZATION_SCHEME}\s+/, '')
          else
            token = params[TOKEN_QUERY_PARAM]
          end

          request.env['msf.token_from_file'].nil? ? auth_from_db(token) : auth_from_file(token)
        end
      end

      # Authenticates the user associated with the API token from the DB
      def auth_from_db(token)
        db_manager = env['msf.db_manager']
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

      # Authenticates the API token from a configuration file
      def auth_from_file(token)
        token == request.env['msf.token_from_file'] ? success!({message: "Successful auth from file token"}) : fail!
      end
    end
  end
end
