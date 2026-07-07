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
    end
  end
end
