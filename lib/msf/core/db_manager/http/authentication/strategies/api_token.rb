module Authentication
  module Strategies
    module ApiToken
      AUTHORIZATION = 'HTTP_AUTHORIZATION'
      AUTHORIZATION_SCHEME = 'Bearer'
      TOKEN_QUERY_PARAM = 'token'

      Warden::Strategies.add(:api_token) do

        # Check if request contains valid data and should be authenticated.
        # @return [Boolean] true if strategy should be run for the request; otherwise, false.
        def valid?
          authorization = request.env[AUTHORIZATION]
          (authorization.is_a?(String) && authorization.start_with?(AUTHORIZATION_SCHEME)) || !params[TOKEN_QUERY_PARAM].nil?
        end

        # Authenticate the request.
        def authenticate!
          db_manager = env['DBManager']
          authorization = request.env[AUTHORIZATION]
          if authorization.is_a?(String) && authorization.start_with?(AUTHORIZATION_SCHEME)
            token = authorization.sub(/^#{AUTHORIZATION_SCHEME}\s+/, '')
          else
            token = params[TOKEN_QUERY_PARAM]
          end

          user = db_manager.users(persistence_token: token).first

          if user.nil?
            throw(:warden, message: "Invalid API token.")
          else
            success!(user)
          end
        end
      end
    end
  end
end