require 'faraday'
require 'set'

# Adapted from lostisland/faraday_middleware. Trimmed down to just the logic
# that we need for octokit.rb.
#
# https://github.com/lostisland/faraday_middleware/blob/138766e/lib/faraday_middleware/response/follow_redirects.rb

module Octokit

  module Middleware

    # Public: Exception thrown when the maximum amount of requests is exceeded.
    class RedirectLimitReached < Faraday::Error::ClientError
      attr_reader :response

      def initialize(response)
        super "too many redirects; last one to: #{response['location']}"
        @response = response
      end
    end

    # Public: Follow HTTP 301, 302, 303, and 307 redirects.
    #
    # For HTTP 303, the original GET, POST, PUT, DELETE, or PATCH request gets
    # converted into a GET. For HTTP 301, 302, and 307, the HTTP method remains
    # unchanged.
    #
    # This middleware currently only works with synchronous requests; i.e. it
    # doesn't support parallelism.
    class FollowRedirects < Faraday::Middleware
      # HTTP methods for which 30x redirects can be followed
      ALLOWED_METHODS = Set.new [:head, :options, :get, :post, :put, :patch, :delete]

      # HTTP redirect status codes that this middleware implements
      REDIRECT_CODES  = Set.new [301, 302, 303, 307]

      # Keys in env hash which will get cleared between requests
      ENV_TO_CLEAR    = Set.new [:status, :response, :response_headers]

      # Default value for max redirects followed
      FOLLOW_LIMIT = 3

      # Regex that matches characters that need to be escaped in URLs, sans
      # the "%" character which we assume already represents an escaped
      # sequence.
      URI_UNSAFE = /[^\-_.!~*'()a-zA-Z\d;\/?:@&=+$,\[\]%]/

      # Public: Initialize the middleware.
      #
      # options - An options Hash (default: {}):
      #           :limit               - A Integer redirect limit (default: 3).
      def initialize(app, options = {})
        super(app)
        @options = options

        @convert_to_get = Set.new [303]
      end

      def call(env)
        perform_with_redirection(env, follow_limit)
      end

      private

      def convert_to_get?(response)
        ![:head, :options].include?(response.env[:method]) &&
          @convert_to_get.include?(response.status)
      end

      def perform_with_redirection(env, follows)
        request_body = env[:body]
        response = @app.call(env)

        response.on_complete do |response_env|
          if follow_redirect?(response_env, response)
            raise(RedirectLimitReached, response) if follows.zero?
            new_request_env = update_env(response_env, request_body, response)
            response = perform_with_redirection(new_request_env, follows - 1)
          end
        end
        response
      end

      def update_env(env, request_body, response)
        original_url = env[:url]
        env[:url] += safe_escape(response["location"])
        unless same_host?(original_url, env[:url])
          env[:request_headers].delete("Authorization")
        end

        if convert_to_get?(response)
          env[:method] = :get
          env[:body] = nil
        else
          env[:body] = request_body
        end

        ENV_TO_CLEAR.each { |key| env.delete(key) }

        env
      end

      def follow_redirect?(env, response)
        ALLOWED_METHODS.include?(env[:method]) &&
          REDIRECT_CODES.include?(response.status)
      end

      def follow_limit
        @options.fetch(:limit, FOLLOW_LIMIT)
      end

      def same_host?(original_url, redirect_url)
        original_uri = Addressable::URI.parse(original_url)
        redirect_uri = Addressable::URI.parse(redirect_url)

        redirect_uri.host.nil? || original_uri.host == redirect_uri.host
      end

      # Internal: Escapes unsafe characters from a URL which might be a path
      # component only or a fully-qualified URI so that it can be joined onto a
      # URI:HTTP using the `+` operator. Doesn't escape "%" characters so to not
      # risk double-escaping.
      def safe_escape(uri)
        uri.to_s.gsub(URI_UNSAFE) { |match|
          "%" + match.unpack("H2" * match.bytesize).join("%").upcase
        }
      end
    end
  end
end
