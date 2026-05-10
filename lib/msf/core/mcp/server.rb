# frozen_string_literal: true

module Msf::MCP
  ##
  # MCP Server Wrapper for Metasploit Framework
  #
  # This class initializes and manages the MCP server with all registered tools.
  # It provides a clean interface for starting/stopping the server and integrates
  # with the Metasploit client and security layers.
  #
  # The Server expects fully configured and authenticated dependencies to be
  # provided during initialization. It does not handle configuration loading
  # or client authentication - those are responsibilities of the calling code.
  #
  class Server

    ##
    # Initialize the MCP server with required dependencies
    #
    # @param msf_client [Metasploit::Client] Configured and authenticated Metasploit client
    # @param rate_limiter [Security::RateLimiter] Configured rate limiter
    #
    def initialize(msf_client:, rate_limiter:)
      @msf_client = msf_client

      # Create server context (passed to all tool calls)
      # Tools only need msf_client and rate_limiter
      @server_context = {
        msf_client: @msf_client,
        rate_limiter: rate_limiter
      }

      # Create MCP configuration with request lifecycle callbacks
      mcp_config = ::MCP::Configuration.new
      mcp_config.around_request = create_around_request
      mcp_config.exception_reporter = create_exception_reporter

      # Initialize MCP server with all tools
      @mcp_server = ::MCP::Server.new(
        name: 'msfmcp',
        version: Msf::MCP::Application::VERSION,
        tools: [
          Tools::SearchModules,
          Tools::ModuleInfo,
          Tools::HostInfo,
          Tools::ServiceInfo,
          Tools::VulnerabilityInfo,
          Tools::NoteInfo,
          Tools::CredentialInfo,
          Tools::LootInfo
        ],
        server_context: @server_context,
        configuration: mcp_config
      )
    end

    ##
    # Start the MCP server with specified transport
    #
    # @param transport [Symbol] Transport type (:stdio or :http)
    # @param host [String] Host address for HTTP transport (default: 'localhost')
    # @param port [Integer] Port number for HTTP transport (default: 3000)
    #
    # @return [MCP::Server] The MCP server instance (for testing purposes)
    # @raise [ArgumentError] If an unknown transport is specified
    #
    def start(transport: :stdio, host: 'localhost', port: 3000)
      case transport
      when :stdio
        start_stdio
      when :http
        start_http(host, port)
      else
        raise ArgumentError, "Unknown transport: #{transport}. Use :stdio or :http"
      end
    end

    ##
    # Shutdown the MCP server and cleanup resources
    #
    def shutdown
      @msf_client&.shutdown
      @mcp_server = nil
    end

    private

    ##
    # Start stdio transport (for CLI usage)
    #
    # @return [MCP::Server] The MCP server instance (for testing purposes)
    #
    def start_stdio
      transport = ::MCP::Server::Transports::StdioTransport.new(@mcp_server)
      transport.open
      @mcp_server
    end

    ##
    # Start HTTP transport (for web/network usage)
    #
    # The transport implements the Rack app interface (#call), so it is mounted
    # directly. MCP-aware request/response logging is handled by the
    # Middleware::RequestLogger middleware.
    #
    # @param host [String] Host address to bind to
    # @param port [Integer] Port to listen on
    #
    # @return [MCP::Server] The MCP server instance (for testing purposes)
    #
    def start_http(host, port)
      require 'rack'
      require 'rack/handler/puma'

      transport = ::MCP::Server::Transports::StreamableHTTPTransport.new(@mcp_server)

      # Build the Rack application with logging middleware.
      # The transport itself is a Rack app (implements #call).
      rack_app = Rack::Builder.new do
        use Msf::MCP::Middleware::RequestLogger
        run transport
      end

      # Start Puma server using the handler appropriate for the Rack version.
      # Rackup::Handler is available with rackup >= 2.x / Rack 3+;
      # Rack::Handler is used with Rack < 3 and rackup 1.x.
      puma_handler = if defined?(Rackup::Handler)
                       Rackup::Handler::Puma
                     else
                       Rack::Handler::Puma
                     end
      puma_handler.run(
        rack_app,
        Port: port,
        Host: host,
        Silent: true
      )

      @mcp_server
    end

    ##
    # Create around_request callback for MCP SDK
    #
    # This callback wraps every JSON-RPC request handler, providing access to
    # both the instrumentation data and the response result. It replaces the
    # deprecated +instrumentation_callback+ which only fires after completion
    # and does not expose the result.
    #
    # The +data+ hash is populated by the SDK with:
    # - :method — the JSON-RPC method name (e.g. "tools/call", "tools/list")
    # - :tool_name, :prompt_name, :resource_uri — specific handler identifiers
    # - :tool_arguments — arguments passed to a tool call
    # - :client — client info hash (name, version)
    # - :error — error type symbol (e.g. :tool_not_found, :internal_error)
    # - :duration — added in the ensure block after this callback returns
    #
    # @return [Proc] Callback that wraps request execution and logs via Rex
    #
    def create_around_request
      ->(data, &request_handler) do
        result = request_handler.call

        # Build message based on the type of request
        message = if data[:error]
                    "MCP Error: #{data[:error]}"
                  elsif data[:tool_name]
                    "Tool call: #{data[:tool_name]}"
                  elsif data[:prompt_name]
                    "Prompt call: #{data[:prompt_name]}"
                  elsif data[:resource_uri]
                    "Resource call: #{data[:resource_uri]}"
                  elsif data[:method]
                    "Method call: #{data[:method]}"
                  else
                    "MCP request"
                  end

        context = data.dup
        if result
          message = "#{message} (ERROR)" if result[:isError]
          context[:result] = result
        end

        if data[:error] || result&.fetch(:isError, nil)
          elog({ message: message, context: context }, LOG_SOURCE, LOG_ERROR)
        else
          ilog({ message: message, context: context }, LOG_SOURCE, LOG_INFO)
        end

        result
      end
    end

    ##
    # Create exception reporter callback for MCP SDK
    #
    # This callback is invoked for any server exception during request processing,
    # which are not tool execution errors.
    # It receives:
    # - exception: The Ruby exception object
    # - context: Hash with :request (JSON string) or :notification (method name string)
    #
    # @return [Proc] Callback that logs exceptions via Rex
    #
    def create_exception_reporter
      ->(exception, context) do
        return unless exception || context

        # Determine the context type and parse data
        error_context = {}

        if context&.fetch(:request, nil)
          error_context[:type] = 'request'
          request = nil
          begin
            request = JSON.parse(context[:request])
          rescue JSON::ParserError
            # Not valid JSON, log raw data
            error_context[:raw_data] = context[:request].inspect
          else
            error_context[:method] = request['method'] if request['method']
            error_context[:params] = request['params'] if request['params']
          end
        elsif context&.fetch(:notification, nil)
          error_context[:type] = 'notification'
          # context[:notification] is the notification method name (string)
          error_context[:method] = context[:notification]
        else
          error_context[:type] = 'unknown'
          error_context[:raw_data] = context.inspect
        end

        elog({
          message: "Error during #{error_context[:type]} processing#{error_context[:method] ? " (#{error_context[:method]})" : ''}",
          exception: exception,
          context: error_context
        }, LOG_SOURCE, LOG_ERROR)
      end
    end
  end
end
