# frozen_string_literal: true

require 'msf/core/mcp'
require 'optparse'

module Msf::MCP
  # Main application class that orchestrates the MCP server startup and lifecycle
  class Application
    VERSION = '0.1.0'
    BANNER = <<~BANNER
      MSF MCP Server v#{VERSION}
      Model Context Protocol server for Metasploit Framework
    BANNER

    # For testing purposes:
    attr_reader :config, :msf_client, :mcp_server, :rate_limiter, :options, :rpc_manager

    # Initialize the application with command-line arguments
    #
    # @param argv [Array<String>] Command-line arguments
    # @param output [IO] Output stream for messages (default: $stderr)
    def initialize(argv = ARGV, output: $stderr)
      @argv = argv.dup
      @output = output
      @options = {}
      @config = nil
      @msf_client = nil
      @mcp_server = nil
      @rate_limiter = nil
      @rpc_manager = nil
    end

    # Run the application
    #
    # @return [void]
    def run
      parse_arguments
      install_signal_handlers
      load_configuration
      validate_configuration
      initialize_logger
      initialize_rate_limiter
      ensure_rpc_server
      initialize_metasploit_client
      authenticate_metasploit
      initialize_mcp_server
      start_mcp_server
    rescue Msf::MCP::Config::ValidationError, Msf::MCP::Config::ConfigurationError => e
      handle_configuration_error(e)
    rescue Msf::MCP::Metasploit::ConnectionError => e
      handle_connection_error(e)
    rescue Msf::MCP::Metasploit::APIError => e
      handle_api_error(e)
    rescue Msf::MCP::Metasploit::AuthenticationError => e
      handle_authentication_error(e)
    rescue Msf::MCP::Metasploit::RpcStartupError => e
      handle_rpc_startup_error(e)
    rescue StandardError => e
      handle_fatal_error(e)
    end

    # Shutdown the application gracefully
    #
    # Performs cleanup operations before process termination:
    # - Logs shutdown event via Rex
    # - Closes MCP server and Metasploit client connections
    # - Cleans up resources
    #
    # @param signal [String] Signal name (e.g., 'INT', 'TERM')
    # @return [void]
    def shutdown(signal = 'INT')
      ilog({
        message: 'Shutting down',
        context: { signal: "SIG#{signal}" }
      }, LOG_SOURCE, LOG_INFO)
      @mcp_server&.shutdown
      @rpc_manager&.stop_rpc_server
      @output.puts "\nShutdown complete"
    end

    private

    # Parse command-line arguments
    #
    # @return [void]
    def parse_arguments
      parser = OptionParser.new do |opts|
        opts.banner = BANNER + "\nUsage: msfmcp [options]"

        opts.on('--config PATH', 'Path to configuration file') do |path|
          @options[:config_path] = File.expand_path(path)
        end

        opts.on('--enable-logging', 'Enable file logging') do
          @options[:enable_logging_cli] = true
        end

        opts.on('--log-file PATH', 'Log file path (overrides config file)') do |path|
          @options[:log_file_cli] = path
        end

        opts.on('--user USER', 'MSF API username (for MessagePack auth)') do |user|
          @options[:msf_user_cli] = user
        end

        opts.on('--password PASS', 'MSF API password (for MessagePack auth)') do |password|
          @options[:msf_password_cli] = password
        end

        opts.on('--no-auto-start-rpc', 'Disable automatic RPC server startup') do
          @options[:no_auto_start_rpc] = true
        end

        opts.on('--mcp-transport TRANSPORT', 'MCP server transport type (\'stdio\' or \'http\')') do |transport|
          @options[:mcp_transport] = transport
        end

        opts.on('-h', '--help', 'Show this help message') do
          @output.puts opts
          exit 0
        end

        opts.on('-v', '--version', 'Show version information') do
          @output.puts "msfmcp version #{VERSION}"
          exit 0
        end
      end

      parser.parse!(@argv)
    end

    # Register a Rex log source when logging is enabled.
    #
    # Selects a JsonFlatfile sink pointed at the configured log path and wraps it
    # with the sanitizing middleware unless sanitization has been explicitly
    # disabled in the config.
    #
    # Priority: CLI flags > config file > defaults
    #
    # @return [void]
    def initialize_logger
      return unless @options[:enable_logging_cli] || @config.dig(:logging, :enabled)

      log_file = @options[:log_file_cli] || @config.dig(:logging, :log_file)
      level = @config.dig(:logging, :level)
      threshold = case @config.dig(:logging, :level).upcase
                  when 'DEBUG'
                    Rex::Logging::LEV_3
                  when 'INFO'
                    Rex::Logging::LEV_2
                  when 'WARN'
                    Rex::Logging::LEV_1
                  when 'ERROR'
                    Rex::Logging::LEV_0
                  end
      inner = Msf::MCP::Logging::Sinks::JsonFlatfile.new(log_file)
      sink  = @config.dig(:logging, :sanitize) ? Msf::MCP::Logging::Sinks::Sanitizing.new(inner) : inner

      deregister_log_source(LOG_SOURCE) if log_source_registered?(LOG_SOURCE)
      register_log_source(LOG_SOURCE, sink, threshold)
    end

    # Install signal handlers for graceful shutdown
    #
    # @return [void]
    def install_signal_handlers
      Signal.trap('INT') { shutdown('INT'); exit 0 }
      Signal.trap('TERM') { shutdown('TERM'); exit 0 }
    end

    # Load configuration from file or use defaults
    #
    # @return [void]
    def load_configuration
      if @options[:config_path]
        @output.puts "Loading configuration from #{@options[:config_path]}"
        @config = Msf::MCP::Config::Loader.load(@options[:config_path])
      else
        @output.puts "No configuration file specified, using defaults"
        @config = Msf::MCP::Config::Loader.load_from_hash({})
      end

      # Apply CLI authentication overrides (highest priority)
      if @options[:msf_user_cli]
        @config[:msf_api][:user] = @options[:msf_user_cli]
      end
      if @options[:msf_password_cli]
        @config[:msf_api][:password] = @options[:msf_password_cli]
      end
      if @options[:no_auto_start_rpc]
        @config[:msf_api][:auto_start_rpc] = false
      end
      if @options[:mcp_transport]
        @config[:mcp][:transport] = @options[:mcp_transport]
      end
    end

    # Validate the loaded configuration
    #
    # @return [void]
    def validate_configuration
      @output.puts "Validating configuration..."
      Msf::MCP::Config::Validator.validate!(@config)
      @output.puts "Configuration valid"
    end

    # Initialize the rate limiter
    #
    # @return [void]
    def initialize_rate_limiter
      @rate_limiter = Msf::MCP::Security::RateLimiter.new(
        requests_per_minute: @config.dig(:rate_limit, :requests_per_minute) || 60,
        burst_size: @config.dig(:rate_limit, :burst_size)
      )
    end

    # Ensure the Metasploit RPC server is available, auto-starting if needed
    #
    # @return [void]
    def ensure_rpc_server
      @rpc_manager = Msf::MCP::RpcManager.new(
        config: @config,
        output: @output
      )
      @rpc_manager.ensure_rpc_available
    end

    # Initialize the Metasploit client
    #
    # @return [void]
    def initialize_metasploit_client
      @output.puts "Connecting to Metasploit RPC at #{@config[:msf_api][:host]}:#{@config[:msf_api][:port]}"
      @msf_client = Msf::MCP::Metasploit::Client.new(
        api_type: @config[:msf_api][:type],
        host: @config[:msf_api][:host],
        port: @config[:msf_api][:port],
        endpoint: @config[:msf_api][:endpoint],
        token: @config[:msf_api][:token],
        ssl: @config[:msf_api][:ssl]
      )
    end

    # Authenticate with Metasploit if using MessagePack
    #
    # @return [void]
    def authenticate_metasploit
      if @config[:msf_api][:type] == 'messagepack'
        @output.puts "Authenticating with Metasploit..."
        @msf_client.authenticate(@config[:msf_api][:user].to_s, @config[:msf_api][:password].to_s)
        @output.puts "Authentication successful"
      else
        @output.puts "Using JSON-RPC with token authentication"
      end
    end

    # Initialize the MCP server
    #
    # @return [void]
    def initialize_mcp_server
      @output.puts "Initializing MCP server..."
      @mcp_server = Msf::MCP::Server.new(
        msf_client: @msf_client,
        rate_limiter: @rate_limiter
      )
    end

    # Start the MCP server with configured transport
    #
    # @return [void]
    def start_mcp_server
      transport = (@config.dig(:mcp, :transport) || 'stdio').to_sym
      host = @config.dig(:mcp, :host) || 'localhost'
      port = @config.dig(:mcp, :port) || 3000

      if transport == :http
        @output.puts "Starting MCP server on HTTP transport..."
        @output.puts "Server listening on http://#{host}:#{port}"
        @output.puts "Press Ctrl+C to shutdown"
        @mcp_server.start(transport: :http, host: host, port: port)
      else
        @output.puts "Starting MCP server on stdio transport..."
        @output.puts "Server ready - waiting for MCP requests"
        @output.puts "Press Ctrl+C to shutdown"
        @mcp_server.start(transport: :stdio)
      end
    end

    # Error handlers

    def handle_configuration_error(error)
      @output.puts "Configuration validation failed: #{error.message}"
      exit 1
    end

    def handle_connection_error(error)
      elog({
        message: 'Connection error',
        context: { host: @config[:msf_api][:host], port: @config[:msf_api][:port] },
        exception: error
      }, LOG_SOURCE, LOG_ERROR)
      @output.puts "Connection error to Metasploit RPC at #{@config[:msf_api][:host]}:#{@config[:msf_api][:port]} - #{error.message}"
      exit 1
    end

    def handle_api_error(error)
      elog({ message: 'Metasploit API error', exception: error }, LOG_SOURCE, LOG_ERROR)
      @output.puts "Metasploit API error: #{error.message}"
      exit 1
    end

    def handle_authentication_error(error)
      elog({
        message: 'Authentication error',
        context: { username: @config[:msf_api][:user].to_s },
        exception: error
      }, LOG_SOURCE, LOG_ERROR)
      @output.puts "Authentication error (username: #{@config[:msf_api][:user]}): #{error.message}"
      exit 1
    end

    def handle_rpc_startup_error(error)
      elog({ message: 'RPC startup error', exception: error }, LOG_SOURCE, LOG_ERROR)
      @output.puts "RPC startup error: #{error.message}"
      exit 1
    end

    def handle_fatal_error(error)
      elog({ message: 'Fatal error during startup', exception: error }, LOG_SOURCE, LOG_ERROR)
      @output.puts "Fatal error: #{error.message}"
      @output.puts error.backtrace.first(5).join("\n") if error.backtrace
      exit 1
    end
  end
end
