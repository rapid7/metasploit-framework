# frozen_string_literal: true

module Msf::MCP
  ##
  # Base error class for all Msf::MCP errors
  #
  class Error < StandardError; end

  ##
  # Configuration Layer Errors
  #
  module Config

    class ConfigurationError < Error; end

    class ValidationError < Error
      attr_reader :errors

      def initialize(errors = {})
        @errors = errors
        super(build_message)
      end

      private

      def build_message
        return "Configuration validation failed" if @errors.empty?

        messages = @errors.map { |field, error| "#{field} #{error}" }
        "Configuration validation failed:\n  - #{messages.join("\n  - ")}"
      end
    end

  end

  ##
  # Security Layer Errors
  #
  module Security

    class ValidationError < Error; end

    class RateLimitExceededError < Error
      attr_reader :retry_after

      def initialize(retry_after)
        @retry_after = retry_after
        super("Rate limit exceeded. Retry after #{retry_after} seconds.")
      end
    end

  end

  ##
  # Metasploit Client Layer Errors
  #
  module Metasploit

    class AuthenticationError < Error; end

    class ConnectionError < Error; end

    class APIError < Error; end

    class RpcStartupError < Error; end

  end

end
