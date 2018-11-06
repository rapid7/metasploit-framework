require 'octokit/middleware/follow_redirects'
require 'octokit/response/raise_error'
require 'octokit/response/feed_parser'
require 'octokit/version'

module Octokit

  # Default configuration options for {Client}
  module Default

    # Default API endpoint
    API_ENDPOINT = "https://api.github.com".freeze

    # Default User Agent header string
    USER_AGENT   = "Octokit Ruby Gem #{Octokit::VERSION}".freeze

    # Default media type
    MEDIA_TYPE   = "application/vnd.github.v3+json".freeze

    # Default WEB endpoint
    WEB_ENDPOINT = "https://github.com".freeze

    # In Faraday 0.9, Faraday::Builder was renamed to Faraday::RackBuilder
    RACK_BUILDER_CLASS = defined?(Faraday::RackBuilder) ? Faraday::RackBuilder : Faraday::Builder

    # Default Faraday middleware stack
    MIDDLEWARE = RACK_BUILDER_CLASS.new do |builder|
      builder.use Faraday::Request::Retry, exceptions: [Octokit::ServerError]
      builder.use Octokit::Middleware::FollowRedirects
      builder.use Octokit::Response::RaiseError
      builder.use Octokit::Response::FeedParser
      builder.adapter Faraday.default_adapter
    end

    class << self

      # Configuration options
      # @return [Hash]
      def options
        Hash[Octokit::Configurable.keys.map{|key| [key, send(key)]}]
      end

      # Default access token from ENV
      # @return [String]
      def access_token
        ENV['OCTOKIT_ACCESS_TOKEN']
      end

      # Default API endpoint from ENV or {API_ENDPOINT}
      # @return [String]
      def api_endpoint
        ENV['OCTOKIT_API_ENDPOINT'] || API_ENDPOINT
      end

      # Default pagination preference from ENV
      # @return [String]
      def auto_paginate
        ENV['OCTOKIT_AUTO_PAGINATE']
      end

      # Default bearer token from ENV
      # @return [String]
      def bearer_token
        ENV['OCTOKIT_BEARER_TOKEN']
      end

      # Default OAuth app key from ENV
      # @return [String]
      def client_id
        ENV['OCTOKIT_CLIENT_ID']
      end

      # Default OAuth app secret from ENV
      # @return [String]
      def client_secret
        ENV['OCTOKIT_SECRET']
      end

      # Default management console password from ENV
      # @return [String]
      def management_console_password
        ENV['OCTOKIT_ENTERPRISE_MANAGEMENT_CONSOLE_PASSWORD']
      end

      # Default management console endpoint from ENV
      # @return [String]
      def management_console_endpoint
        ENV['OCTOKIT_ENTERPRISE_MANAGEMENT_CONSOLE_ENDPOINT']
      end

      # Default options for Faraday::Connection
      # @return [Hash]
      def connection_options
        {
          :headers => {
            :accept => default_media_type,
            :user_agent => user_agent
          }
        }
      end

      # Default media type from ENV or {MEDIA_TYPE}
      # @return [String]
      def default_media_type
        ENV['OCTOKIT_DEFAULT_MEDIA_TYPE'] || MEDIA_TYPE
      end

      # Default GitHub username for Basic Auth from ENV
      # @return [String]
      def login
        ENV['OCTOKIT_LOGIN']
      end

      # Default middleware stack for Faraday::Connection
      # from {MIDDLEWARE}
      # @return [Faraday::RackBuilder or Faraday::Builder]
      def middleware
        MIDDLEWARE
      end

      # Default GitHub password for Basic Auth from ENV
      # @return [String]
      def password
        ENV['OCTOKIT_PASSWORD']
      end

      # Default pagination page size from ENV
      # @return [Integer] Page size
      def per_page
        page_size = ENV['OCTOKIT_PER_PAGE']

        page_size.to_i if page_size
      end

      # Default proxy server URI for Faraday connection from ENV
      # @return [String]
      def proxy
        ENV['OCTOKIT_PROXY']
      end

      # Default SSL verify mode from ENV
      # @return [Integer]
      def ssl_verify_mode
        # 0 is OpenSSL::SSL::VERIFY_NONE
        # 1 is OpenSSL::SSL::SSL_VERIFY_PEER
        # the standard default for SSL is SSL_VERIFY_PEER which requires a server certificate check on the client
        ENV.fetch('OCTOKIT_SSL_VERIFY_MODE', 1).to_i
      end

      # Default User-Agent header string from ENV or {USER_AGENT}
      # @return [String]
      def user_agent
        ENV['OCTOKIT_USER_AGENT'] || USER_AGENT
      end

      # Default web endpoint from ENV or {WEB_ENDPOINT}
      # @return [String]
      def web_endpoint
        ENV['OCTOKIT_WEB_ENDPOINT'] || WEB_ENDPOINT
      end

      # Default behavior for reading .netrc file
      # @return [Boolean]
      def netrc
        ENV['OCTOKIT_NETRC'] || false
      end

      # Default path for .netrc file
      # @return [String]
      def netrc_file
        ENV['OCTOKIT_NETRC_FILE'] || File.join(ENV['HOME'].to_s, '.netrc')
      end

    end
  end
end
