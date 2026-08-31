# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # Raised when a tool annotated as dangerous is invoked but the server is
    # not running with dangerous actions mode enabled.
    #
    class DangerousModeDisabledError < ::Msf::MCP::Error; end

    ##
    # Shared helper methods for MCP tools.
    #
    # Provides a standard way to build error responses that comply with the
    # MCP protocol, returning a normal result with `isError: true` instead
    # of raising exceptions that the MCP server would wrap as internal errors.
    #
    module ToolHelper
      DANGEROUS_MODE_DISABLED_MESSAGE = 'This tool requires dangerous actions mode to be enabled. ' \
        'Enable it with: --enable-dangerous-actions flag, MSF_MCP_DANGEROUS_ACTIONS=true environment ' \
        'variable, or mcp.dangerous_actions: true in config file.'

      ##
      # Build a standard MCP error response.
      #
      # @param message [String] Human-readable error message
      # @return [::MCP::Tool::Response] Response with isError flag set
      #
      def tool_error_response(message)
        ::MCP::Tool::Response.new(
          [{ type: 'text', text: message }],
          error: true
        )
      end

      ##
      # Guard a dangerous tool invocation by checking the dangerous_actions
      # flag in the server context.
      #
      # @param server_context [Hash] Server context with :dangerous_actions key
      # @raise [DangerousModeDisabledError] If dangerous mode is not enabled
      # @return [void]
      #
      def dangerous_mode_required!(server_context)
        return if server_context[:dangerous_actions] == true

        raise DangerousModeDisabledError, DANGEROUS_MODE_DISABLED_MESSAGE
      end

      ##
      # Wrap a tool's call body with the standard dangerous-mode gate, rate
      # limiter check, and error-to-response mapping. Yields the msf_client
      # to the caller so the block only has to do input validation, the RPC
      # call, and response shaping.
      #
      # Any exception raised by the block that matches one of the well-known
      # MCP error classes is converted into an MCP tool error response via
      # {#tool_error_response}. Other exceptions propagate to the MCP server
      # so it can render them as internal errors.
      #
      # @param server_context [Hash] The tool's server context. Must contain
      #   :msf_client and :rate_limiter. When dangerous: true, must also
      #   contain :dangerous_actions.
      # @param rate_limit_key [String] Rate limiter bucket name, typically the
      #   tool name without the msf_ prefix.
      # @param dangerous [Boolean] When true, calls {#dangerous_mode_required!}
      #   before the rate-limit check so a blocked tool never consumes rate.
      # @yieldparam msf_client [Msf::MCP::Metasploit::Client] Framework RPC client
      # @return [::MCP::Tool::Response]
      #
      def with_tool_context(server_context, rate_limit_key, dangerous: false)
        dangerous_mode_required!(server_context) if dangerous
        rate_limiter = server_context[:rate_limiter]
        rate_limiter.check_rate_limit!(rate_limit_key)
        yield server_context[:msf_client]
      rescue Msf::MCP::Tools::DangerousModeDisabledError, Msf::MCP::Security::ValidationError => e
        tool_error_response(e.message)
      rescue Msf::MCP::Security::RateLimitExceededError => e
        tool_error_response("Rate limit exceeded: #{e.message}")
      rescue Msf::MCP::Metasploit::AuthenticationError => e
        tool_error_response("Authentication failed: #{e.message}")
      rescue Msf::MCP::Metasploit::APIError => e
        tool_error_response("Metasploit API error: #{e.message}")
      end
    end
  end
end
