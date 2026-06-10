# frozen_string_literal: true

require 'msf/core/mcp'

module Msf
  ###
  #
  # This plugin manages the lifecycle of the Metasploit MCP (Model Context Protocol)
  # server from within the msfconsole session.
  #
  ###
  class Plugin::MCP < Msf::Plugin

    #
    # Console command dispatcher for the `mcp` command and its subcommands.
    #
    class McpCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      # Guard against redefinition when msfconsole's plugin system loads the file twice
      SUBCOMMANDS = %w[status start stop restart help].freeze unless defined?(SUBCOMMANDS)

      # Valid option keys accepted by `mcp start` and `mcp restart`
      unless defined?(VALID_OPTIONS)
        VALID_OPTIONS = %w[
          Transport ServerHost ServerPort
          RpcHost RpcPort RpcUser RpcPass RpcSSL
          RateLimit
        ].freeze
      end

      attr_accessor :plugin

      def name
        'MCP'
      end

      def commands
        { 'mcp' => 'Manage the MCP server' }
      end

      def cmd_mcp(*args)
        subcommand = args.shift

        case subcommand
        when 'status'
          mcp_status
        when 'start'
          mcp_start(args)
        when 'stop'
          mcp_stop
        when 'restart'
          mcp_restart(args)
        else
          cmd_mcp_help
        end
      end

      def cmd_mcp_help
        print_line('Usage: mcp <subcommand> [options]')
        print_line
        print_line('Subcommands:')
        print_line('  status  - Display MCP server status')
        print_line('  start   - Start the MCP server')
        print_line('  stop    - Stop the MCP server')
        print_line('  restart - Restart the MCP server')
        print_line('  help    - Show this help message')
        print_line
        print_line('Options (for start/restart):')
        print_line('  Transport=<http>            MCP transport type (default: http)')
        print_line('  ServerHost=<host>           MCP server bind address (default: localhost)')
        print_line('  ServerPort=<port>           MCP server port (default: 3000)')
        print_line('  RpcHost=<host>              RPC server host (default: localhost)')
        print_line('  RpcPort=<port>              RPC server port (default: 55552)')
        print_line('  RpcUser=<user>              RPC username (default: msf)')
        print_line('  RpcPass=<pass>              RPC password')
        print_line('  RpcSSL=<true|false>         Use SSL for RPC (default: false)')
        print_line('  RateLimit=<n>               Requests per minute (default: 60)')
        print_line
        print_line('Examples:')
        print_line('  mcp start')
        print_line('  mcp start Transport=http ServerPort=8080')
        print_line('  mcp start RpcUser=msf RpcPass=secret')
        print_line
      end

      def cmd_mcp_tabs(_str, words)
        return SUBCOMMANDS if words.length == 1

        []
      end

      private

      def mcp_status
        plugin.print_mcp_status
      end

      def mcp_start(args)
        opts = parse_options(args)
        return unless opts

        plugin.start_server(opts)
      end

      def mcp_stop
        plugin.stop_server
      end

      def mcp_restart(args)
        opts = parse_options(args)
        return unless opts

        plugin.restart_server(opts)
      end

      # Parses Key=Value pairs from command arguments into an options hash.
      # Returns nil and prints an error if any argument is malformed or unrecognized.
      def parse_options(args)
        opts = {}
        args.each do |arg|
          key, value = arg.split('=', 2)
          unless key && value && !value.empty?
            print_error("Invalid option format: #{arg} (expected Key=Value)")
            return nil
          end
          unless VALID_OPTIONS.include?(key)
            print_error("Unknown option: #{key}")
            print_error("Valid options: #{VALID_OPTIONS.join(', ')}")
            return nil
          end
          opts[key] = value
        end
        opts
      end
    end

    attr_accessor :auto_started_rpc, :mcp_server, :server_thread, :msf_client,
                  :rate_limiter, :server_config, :started_at

    def initialize(framework, opts)
      super

      @server_config = nil
      @auto_started_rpc = false
      register_dispatcher
      print_status("MCP plugin loaded. Use #{Msf::Ui::Tip.highlight('mcp start')} to start the server.")
    end

    #
    # Returns 'mcp'
    #
    def name
      'mcp'
    end

    #
    # Returns the plugin description.
    #
    def desc
      'Manages the Metasploit MCP server from within msfconsole'
    end

    #
    # Cleans up resources when the plugin is unloaded.
    #
    def cleanup
      if @mcp_server
        stop_mcp_server
        print_status('MCP server stopped')
      end
      deregister_dispatcher
      unload_auto_started_rpc
      super
    end

    #
    # Public interface for the command dispatcher to control the server.
    #

    def print_mcp_status
      unless @server_config
        print_status('MCP server status: stopped (not configured)')
        print_status("  Use #{Msf::Ui::Tip.highlight('mcp start')} to configure and start the server")
        return
      end

      mcp_config = @server_config[:mcp]
      transport = mcp_config[:transport]

      if @mcp_server
        print_status('MCP server status: running')
        print_status("  Transport: #{transport}")
        if transport == 'http'
          print_status("  Listening: http://#{mcp_config[:host]}:#{mcp_config[:port]}")
        else
          print_status('  Listening: N/A')
        end
        print_status("  Uptime:    #{format_uptime}")
      else
        print_status('MCP server status: stopped')
        print_status("  Transport: #{transport}")
        print_status('  Listening: N/A')
      end
    end

    def start_server(opts = {})
      if @mcp_server
        print_error('MCP server is already running')
        return
      end

      validate_options!(opts)
      @server_config = resolve_config(opts)
      @server_config[:rpc] = resolve_rpc_config(opts)

      rpc = @server_config[:rpc]
      start_mcp_server(rpc, @server_config)
    rescue StandardError => e
      # Ensure server is left in a clean stopped state on failure
      stop_mcp_server
      unload_auto_started_rpc
      print_error("Failed to start MCP server: #{e.message}")
    end

    def stop_server
      unless @mcp_server
        print_error('MCP server is already stopped')
        return
      end

      stop_mcp_server
      print_status('MCP server stopped')
    end

    def restart_server(opts = {})
      stop_mcp_server if @mcp_server
      unload_auto_started_rpc

      validate_options!(opts)
      @server_config = resolve_config(opts)
      @server_config[:rpc] = resolve_rpc_config(opts)

      rpc = @server_config[:rpc]
      start_mcp_server(rpc, @server_config)
    rescue StandardError => e
      # Ensure server is left in a clean stopped state on failure
      stop_mcp_server
      unload_auto_started_rpc
      print_error("Failed to restart MCP server: #{e.message}")
    end

    private

    def register_dispatcher
      dispatcher = add_console_dispatcher(McpCommandDispatcher)
      dispatcher.plugin = self
    end

    #
    # Creates and starts the MCP server with the resolved configuration.
    #
    def start_mcp_server(rpc, config)
      @msf_client = Msf::MCP::Metasploit::Client.new(
        api_type: 'messagepack',
        host: rpc[:host],
        port: rpc[:port],
        ssl: rpc[:ssl]
      )
      authenticate_with_retry(@msf_client, rpc[:user], rpc[:pass])

      mcp_config = config[:mcp]
      rate_limit = config[:rate_limit]
      transport = mcp_config[:transport]

      @rate_limiter = Msf::MCP::Security::RateLimiter.new(
        requests_per_minute: rate_limit[:requests_per_minute]
      )

      @mcp_server = Msf::MCP::Server.new(
        msf_client: @msf_client,
        rate_limiter: @rate_limiter
      )

      host = mcp_config[:host]
      port = mcp_config[:port]

      @server_thread = framework.threads.spawn('MCPServer', false) do
        if transport == 'http'
          @mcp_server.start(transport: :http, host: host, port: port)
        else
          @mcp_server.start(transport: :stdio)
        end
      end

      @started_at = Time.now
      print_server_status(mcp_config)
    rescue Msf::MCP::Metasploit::AuthenticationError => e
      raise Msf::MCP::Metasploit::AuthenticationError, "RPC authentication failed: #{e.message}"
    rescue Msf::MCP::Metasploit::ConnectionError => e
      raise Msf::MCP::Metasploit::ConnectionError, "RPC connection failed: #{e.message}"
    rescue Errno::EADDRINUSE
      raise Msf::MCP::Error, "Address already in use: #{mcp_config[:host]}:#{mcp_config[:port]}"
    end

    def print_server_status(mcp_config)
      if mcp_config[:transport] == 'stdio'
        print_status('MCP server started (transport: stdio)')
      else
        print_status("MCP server started on #{mcp_config[:host]}:#{mcp_config[:port]} (transport: http)")
      end
    end

    def format_uptime
      return 'N/A' unless @started_at

      elapsed = (Time.now - @started_at).to_i
      hours = elapsed / 3600
      minutes = (elapsed % 3600) / 60
      seconds = elapsed % 60

      parts = []
      parts << "#{hours}h" if hours > 0
      parts << "#{minutes}m" if minutes > 0 || hours > 0
      parts << "#{seconds}s"
      parts.join(' ')
    end

    def stop_mcp_server
      @mcp_server&.shutdown
      terminate_server_thread
      @mcp_server = nil
      @server_thread = nil
      @msf_client = nil
      @rate_limiter = nil
      @started_at = nil
    end

    # Retries RPC authentication to allow time for an auto-started msgrpc
    # server to bind its port before we attempt to connect.
    def authenticate_with_retry(client, user, pass, max_attempts: 10, delay: 0.5)
      retries = @auto_started_rpc ? max_attempts : 1
      attempts = 0
      begin
        attempts += 1
        client.authenticate(user, pass)
      rescue Msf::MCP::Metasploit::ConnectionError
        if attempts < retries
          sleep(delay)
          retry
        end
        raise
      end
    end

    # Waits for graceful thread exit, then force kills if necessary
    def terminate_server_thread
      return unless @server_thread&.alive?

      unless @server_thread.join(5)
        @server_thread.kill
        print_warning('MCP server thread did not terminate gracefully, forced kill')
      end
    end

    def deregister_dispatcher
      remove_console_dispatcher('MCP')
    rescue StandardError => e
      print_warning("Failed to deregister MCP console dispatcher: #{e.message}")
    end

    def unload_auto_started_rpc
      return unless @auto_started_rpc

      begin
        msgrpc = framework.plugins.find { |p| p.name == 'msgrpc' }
        if msgrpc
          # Give msgrpc server time to initialize before attempting unload
          sleep(0.5) unless msgrpc.respond_to?(:server) && msgrpc.server
          framework.plugins.unload(msgrpc)
        end
      rescue StandardError => e
        print_warning("Failed to unload auto-started msgrpc: #{e.message}")
      end
      @auto_started_rpc = false
    end

    #
    # Validates options before starting the server.
    # Raises Msf::MCP::Config::ValidationError if any option value is invalid.
    #
    def validate_options!(opts)
      validate_port_option!(opts, 'ServerPort')
      validate_port_option!(opts, 'RpcPort')
      validate_transport_option!(opts)
      validate_rpc_ssl_option!(opts)
      validate_rate_limit_option!(opts)
      validate_rpc_credentials!(opts)
    end

    def validate_port_option!(opts, key)
      return unless opts[key]

      port = Integer(opts[key], exception: false)
      if port.nil? || port < 1 || port > 65_535
        option_error(key, 'an integer between 1 and 65535')
      end
    end

    def validate_transport_option!(opts)
      return unless opts['Transport']

      # stdio transport is not supported from msfconsole; use msfmcpd for stdio
      unless opts['Transport'] == 'http'
        option_error('Transport', "\"http\" (stdio is only supported via #{Msf::Ui::Tip.highlight('msfmcpd')})")
      end
    end

    def validate_rpc_ssl_option!(opts)
      return unless opts['RpcSSL']

      unless %w[true false].include?(opts['RpcSSL'])
        option_error('RpcSSL', '"true" or "false"')
      end
    end

    def validate_rate_limit_option!(opts)
      return unless opts['RateLimit']

      value = Integer(opts['RateLimit'], exception: false)
      if value.nil? || value < 1 || value > 10_000
        option_error('RateLimit', 'an integer between 1 and 10000')
      end
    end

    def validate_rpc_credentials!(opts)
      has_user = opts['RpcUser'] && !opts['RpcUser'].empty?
      has_pass = opts['RpcPass'] && !opts['RpcPass'].empty?

      if has_user && !has_pass
        option_error('RpcPass', 'a value (both RpcUser and RpcPass are required)')
      elsif has_pass && !has_user
        option_error('RpcUser', 'a value (both RpcUser and RpcPass are required)')
      end
    end

    #
    # Translates validated plugin options into the internal configuration hash
    # used by the MCP server components.
    #
    def resolve_config(opts)
      transport = opts['Transport'] || 'http'

      mcp_config = { transport: transport }
      unless transport == 'stdio'
        mcp_config[:host] = opts['ServerHost'] || Msf::MCP::Config::Defaults::MCP_HOST
        mcp_config[:port] = Integer(opts['ServerPort'] || Msf::MCP::Config::Defaults::MCP_PORT)
      end

      rate_limit_value = Integer(opts['RateLimit'] || Msf::MCP::Config::Defaults::RATE_LIMIT_REQUESTS_PER_MINUTE)

      {
        mcp: mcp_config,
        rate_limit: {
          requests_per_minute: rate_limit_value,
          burst_size: rate_limit_value
        }
      }
    end

    #
    # Resolves RPC connection configuration using a priority-based approach:
    # introspect loaded msgrpc (with explicit option overrides) > explicit only > auto-start msgrpc.
    #
    def resolve_rpc_config(opts)
      @auto_started_rpc = false

      if (msgrpc = find_loaded_msgrpc)
        introspect_msgrpc(msgrpc, opts)
      elsif explicit_rpc_credentials?(opts)
        resolve_explicit_rpc(opts)
      else
        auto_start_msgrpc(opts)
      end
    end

    def explicit_rpc_credentials?(opts)
      (opts['RpcPass'] && !opts['RpcPass'].empty?) ||
        (opts['RpcUser'] && !opts['RpcUser'].empty?)
    end

    # Explicit credentials provided — connect to external or local RPC
    def resolve_explicit_rpc(opts)
      {
        host: opts['RpcHost'] || Msf::MCP::Config::Defaults::RPC_HOST,
        port: Integer(opts['RpcPort'] || Msf::MCP::Config::Defaults::MSGRPC_PORT),
        user: opts['RpcUser'] || Msf::MCP::Config::Defaults::RPC_USER,
        pass: opts['RpcPass'],
        ssl: (opts['RpcSSL'] || 'false') == 'true'
      }
    end

    def find_loaded_msgrpc
      framework.plugins.find { |p| p.name == 'msgrpc' }
    end

    # Extract connection details from a running msgrpc plugin instance
    def introspect_msgrpc(plugin, opts)
      server = plugin.server
      user, pass = server.users.first

      {
        host: opts['RpcHost'] || server.srvhost,
        port: Integer(opts['RpcPort'] || server.srvport),
        user: opts['RpcUser'] || user,
        pass: opts['RpcPass'] || pass,
        ssl: resolve_ssl(opts, server)
      }
    end

    def resolve_ssl(opts, server)
      if opts['RpcSSL']
        opts['RpcSSL'] == 'true'
      else
        server.options[:ssl] ? true : false
      end
    end

    # No msgrpc loaded and no explicit creds — start one automatically
    def auto_start_msgrpc(opts)
      pass = Rex::Text.rand_text_alphanumeric(12)
      user = Msf::MCP::Config::Defaults::RPC_USER

      msgrpc_opts = {
        'Pass' => pass,
        'User' => user,
        'ServerHost' => Msf::MCP::Config::Defaults::RPC_HOST,
        'ServerPort' => Msf::MCP::Config::Defaults::MSGRPC_PORT,
        'SSL' => 'true'
      }

      framework.plugins.load('msgrpc', msgrpc_opts)
      @auto_started_rpc = true

      print_status("Auto-started msgrpc - User: #{user}, Pass: #{pass}")

      {
        host: opts['RpcHost'] || Msf::MCP::Config::Defaults::RPC_HOST,
        port: Integer(opts['RpcPort'] || Msf::MCP::Config::Defaults::MSGRPC_PORT),
        user: user,
        pass: pass,
        ssl: (opts['RpcSSL'] || 'true') == 'true'
      }
    end

    def option_error(option_name, expected_format)
      error_detail = "Invalid value for #{option_name}: expected #{expected_format}"
      raise Msf::MCP::Config::ValidationError, { option_name => error_detail }
    end

  end
end
