# frozen_string_literal: true

module Msf::MCP
  module Middleware
    ##
    # Rack middleware that enforces Bearer token authentication on every request.
    #
    # Skipped (pass-through) when no token is configured -- the token is always
    # present when this middleware is mounted because {Server#start_http} only
    # adds it to the stack when +auth_token+ is non-nil.
    #
    # Clients must send:
    #   Authorization: Bearer <token>
    #
    # Returns 401 with a WWW-Authenticate challenge on any mismatch.
    # Comparison is constant-time via +Rack::Utils.secure_compare+ to prevent
    # timing-based token enumeration.
    #
    class BearerAuth
      UNAUTHORIZED = [
        401,
        {
          'Content-Type'    => 'application/json',
          'WWW-Authenticate' => 'Bearer realm="msfmcp"'
        },
        ['{"error":"Unauthorized"}']
      ].freeze

      def initialize(app, auth_token:)
        @app        = app
        @auth_token = auth_token
      end

      def call(env)
        expected = "Bearer #{@auth_token}"
        provided = env['HTTP_AUTHORIZATION'].to_s
        return UNAUTHORIZED unless Rack::Utils.secure_compare(expected, provided)

        @app.call(env)
      end
    end
  end
end
