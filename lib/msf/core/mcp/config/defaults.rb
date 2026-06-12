# frozen_string_literal: true

module Msf::MCP
  module Config
    # Shared default values for MCP server configuration.
    # Used by both the msfconsole plugin and the standalone msfmcpd daemon
    # to keep defaults consistent across entry points.
    # Values are aligned with the established msfmcpd defaults.
    module Defaults
      # MCP HTTP server defaults
      MCP_HOST = 'localhost'
      MCP_PORT = 3000

      # RPC connection defaults (for msfrpcd / messagepack RPC)
      RPC_HOST = '127.0.0.1'
      RPC_PORT = 55_553
      RPC_USER = 'msf'
      RPC_SSL = true

      # The msgrpc plugin binds on a different port than msfrpcd
      MSGRPC_PORT = 55_552

      # Rate limiting
      RATE_LIMIT_REQUESTS_PER_MINUTE = 60
    end
  end
end
