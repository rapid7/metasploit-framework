# frozen_string_literal: true

# Main entry point for MSF MCP Server
module Msf
  module MCP
    VERSION = '0.1.0'
  end
end

# Load the base configuration (for default paths, etc.)
require 'msf/base/config'

# Load the base Rex libraries
require 'rex/socket'
require 'rex/logging'
require 'rex/logging/log_sink'

module Msf
  module MCP
    # Log source identifier for all MCP log messages.
    LOG_SOURCE = 'mcp'

    # Log level aliases — semantic names for Rex::Logging level constants.
    LOG_DEBUG = Rex::Logging::LEV_3
    LOG_INFO  = Rex::Logging::LEV_2
    LOG_WARN  = Rex::Logging::LEV_1
    LOG_ERROR = Rex::Logging::LEV_0
  end
end

# Load the MCP-specific logging components
require_relative 'mcp/logging/sinks/json_stream'
require_relative 'mcp/logging/sinks/json_flatfile'
require_relative 'mcp/logging/sinks/sanitizing'
require_relative 'mcp/middleware/request_logger'

# Error classes
require_relative 'mcp/errors'

# Configuration Layer
require_relative 'mcp/config/loader'
require_relative 'mcp/config/validator'

# Security Layer
require_relative 'mcp/security/input_validator'
require_relative 'mcp/security/rate_limiter'

# Metasploit Client Layer
require_relative 'mcp/rpc_manager'
require_relative 'mcp/metasploit/messagepack_client'
require_relative 'mcp/metasploit/jsonrpc_client'
require_relative 'mcp/metasploit/client'
require_relative 'mcp/metasploit/response_transformer'

# MCP SDK
require 'mcp'

# MCP Layer
require_relative 'mcp/tools/tool_helper'
require_relative 'mcp/tools/search_modules'
require_relative 'mcp/tools/module_info'
require_relative 'mcp/tools/host_info'
require_relative 'mcp/tools/service_info'
require_relative 'mcp/tools/vulnerability_info'
require_relative 'mcp/tools/note_info'
require_relative 'mcp/tools/credential_info'
require_relative 'mcp/tools/loot_info'
require_relative 'mcp/server'

# Application Layer
require_relative 'mcp/application'

# Make logging stubs (ilog, elog, dlog, wlog)
include Rex::Logging

