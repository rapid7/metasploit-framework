# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # Shared helper methods for MCP tools.
    #
    # Provides a standard way to build error responses that comply with the
    # MCP protocol, returning a normal result with `isError: true` instead
    # of raising exceptions that the MCP server would wrap as internal errors.
    #
    module ToolHelper
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
    end
  end
end
