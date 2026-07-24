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
    include Msf::Exploit::Retry

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
          AuthToken
          ServerHost ServerPort DangerousActions
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
        print_line('  AuthToken=<token>           MCP server authentication token (default: random, blank: disabled)')
        print_line('  ServerHost=<host>           MCP server bind address (default: localhost)')
        print_line('  ServerPort=<port>           MCP server port (default: 3000)')
        print_line('  DangerousActions=<true|false> Enable destructive tools like module execution and session control (default: false)')
        print_line('  RpcHost=<host>              RPC server host (default: 127.0.0.1)')
        print_line('  RpcPort=<port>              RPC server port (default: 55552)')
        print_line('  RpcUser=<user>              RPC username (default: msf)')
        print_line('  RpcPass=<pass>              RPC password')
        print_line('  RpcSSL=<true|false>         Use SSL for RPC (default: false)')
        print_line('  RateLimit=<n>               Requests per minute (default: 60)')
        print_line
        print_line('Examples:')
        print_line('  mcp start')
        print_line('  mcp start ServerPort=8080')
        print_line('  mcp start RpcUser=msf RpcPass=secret')
        print_line
      end

      def cmd_mcp_tabs(str, words)
        # words[0] is always 'mcp' (the command name itself)
        # When words.length == 1, user is typing the subcommand
        # When words.length >= 2, subcommand is words[1] and user is typing options
        if words.length == 1
          return SUBCOMMANDS.select { |s| s.start_with?(str.downcase) }
        end

        subcommand = words[1]
        if %w[start restart].include?(subcommand)
          VALID_OPTIONS.map { |opt| "#{opt}=" }.select { |o| o.downcase.start_with?(str.downcase) }
        else
          []
        end
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
      # Option keys are case-insensitive and normalized to their canonical form.
      # Returns nil and prints an error if any argument is malformed or unrecognized.
      def parse_options(args)
        opts = {}
        args.each do |arg|
          key, value = arg.split('=', 2)
          # AuthToken can be blank while the others have to be set (blank is explicitly disabled)
          unless key && value && (key.casecmp('AuthToken').zero? || !value.empty?)
            print_error("Invalid option format: #{arg} (expected Key=Value)")
            return nil
          end
          canonical_key = VALID_OPTIONS.find { |opt| opt.casecmp(key).zero? }
          unless canonical_key
            print_error("Unknown option: #{key}")
            print_error("Valid options: #{VALID_OPTIONS.join(', ')}")
            return nil
          end
          opts[canonical_key] = value
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

      if @mcp_server
        print_status('MCP server status: running')
        print_status("  Listening: http://#{Rex::Socket.to_authority(mcp_config[:host], mcp_config[:port])}")
        print_status("  Uptime:    #{format_uptime}")
      else
        print_status('MCP server status: stopped')
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
      # Prevent stale config from making status report a "stopped" server
      @server_config = nil
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
      # Prevent stale config from making status report a "stopped" server
      @server_config = nil
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

      @rate_limiter = Msf::MCP::Security::RateLimiter.new(
        requests_per_minute: rate_limit[:requests_per_minute]
      )

      @mcp_server = Msf::MCP::Server.new(
        msf_client: @msf_client,
        rate_limiter: @rate_limiter,
        dangerous_actions: mcp_config[:dangerous_actions]
      )

      host = mcp_config[:host]
      port = mcp_config[:port]
      if mcp_config.key?(:auth_token)
        auth_token = mcp_config[:auth_token]
        auth_token_generated = false
      else
        auth_token = @mcp_server.class.generate_auth_token
        auth_token_generated = true
      end

      print_status('Starting MCP server on HTTP transport...')
      # Catch port conflicts synchronously before spawning async thread
      verify_port_available!(host, port)

      # Capture reference so the thread isn't affected if shutdown nils @mcp_server
      mcp_server = @mcp_server
      @server_thread = framework.threads.spawn('MCPServer', false) do
        mcp_server.start(transport: :http, host: host, port: port, auth_token: auth_token)
      end

      # Catches TOCTOU races where port freed between pre-flight and spawn
      verify_mcp_server_started!(host, port)

      @started_at = Time.now
      print_status("MCP server listening on http://#{Rex::Socket.to_authority(mcp_config[:host], mcp_config[:port])}/")
      if auth_token_generated
        print_status("Authentication: Bearer token (auto-generated)")
        print_status("  Configure your MCP client with: Authorization: Bearer #{auth_token}")
      else
        print_status("Authentication: #{auth_token ? 'enabled' : 'disabled'}")
      end
      if mcp_config[:dangerous_actions]
        print_warning('Dangerous actions mode is ENABLED. Destructive tools (module execution, session control) are accessible.')
      else
        print_status('Dangerous actions mode is disabled')
      end
    rescue Msf::MCP::Metasploit::AuthenticationError => e
      raise Msf::MCP::Metasploit::AuthenticationError, "RPC authentication failed: #{e.message}"
    rescue Msf::MCP::Metasploit::ConnectionError => e
      raise Msf::MCP::Metasploit::ConnectionError, "RPC connection failed: #{e.message}"
    # Fallback for TOCTOU race: port taken between verify_port_available! and actual bind
    rescue Errno::EADDRINUSE
      raise Msf::MCP::Error, "Address already in use: #{Rex::Socket.to_authority(mcp_config[:host], mcp_config[:port])}"
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
        framework.plugins.unload(msgrpc) if msgrpc
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
      validate_boolean_option!(opts, 'RpcSSL')
      validate_boolean_option!(opts, 'DangerousActions')
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

    def validate_boolean_option!(opts, key)
      return unless opts[key]

      unless %w[true false].include?(opts[key].to_s.downcase)
        option_error(key, '"true" or "false"')
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
      has_host = opts['RpcHost'] && !opts['RpcHost'].empty?

      if has_user && !has_pass
        option_error('RpcPass', 'a value (both RpcUser and RpcPass are required)')
      elsif has_pass && !has_user
        option_error('RpcUser', 'a value (both RpcUser and RpcPass are required)')
      elsif has_host && !has_pass
        option_error('RpcPass', 'a value (RpcPass is required when connecting to a remote RPC host)')
      end
    end

    #
    # Translates validated plugin options into the internal configuration hash
    # used by the MCP server components.
    #
    def resolve_config(opts)
      mcp_config = {
        transport: 'http',
        host: opts['ServerHost'] || Msf::MCP::Config::Defaults::MCP_HOST,
        port: Integer(opts['ServerPort'] || Msf::MCP::Config::Defaults::MCP_PORT),
        dangerous_actions: parse_bool(opts['DangerousActions'],
                                      default: Msf::MCP::Config::Defaults::DANGEROUS_ACTIONS)
      }

      if opts.key?('AuthToken')
        mcp_config[:auth_token] = opts['AuthToken'].blank? ? nil : opts['AuthToken']
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
        result = introspect_msgrpc(msgrpc, opts)
        return result if result
      end

      if explicit_rpc_credentials?(opts)
        resolve_explicit_rpc(opts)
      else
        auto_start_msgrpc(opts)
      end
    end

    def explicit_rpc_credentials?(opts)
      (opts['RpcPass'] && !opts['RpcPass'].empty?) ||
        (opts['RpcUser'] && !opts['RpcUser'].empty?) ||
        (opts['RpcHost'] && !opts['RpcHost'].empty?)
    end

    # Explicit credentials provided — connect to external or local RPC
    def resolve_explicit_rpc(opts)
      {
        host: opts['RpcHost'] || Msf::MCP::Config::Defaults::RPC_HOST,
        port: Integer(opts['RpcPort'] || Msf::MCP::Config::Defaults::MSGRPC_PORT),
        user: opts['RpcUser'] || Msf::MCP::Config::Defaults::RPC_USER,
        pass: opts['RpcPass'],
        ssl: parse_bool(opts['RpcSSL'], default: Msf::MCP::Config::Defaults::RPC_SSL)
      }
    end

    # Skip zombie plugins whose server failed to bind
    def find_loaded_msgrpc
      framework.plugins.find { |p| p.name == 'msgrpc' && p.respond_to?(:server) && p.server }
    end

    # Extract connection details from a running msgrpc plugin instance
    def introspect_msgrpc(plugin, opts)
      server = plugin.server
      # Defensive guard in case server became nil after find_loaded_msgrpc check
      return nil unless server

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
      return parse_bool(opts['RpcSSL'], default: false) if opts['RpcSSL']

      server.options[:ssl] ? true : false
    end

    # No msgrpc loaded and no explicit creds — start one automatically
    def auto_start_msgrpc(opts)
      pass = Rex::Text.rand_text_alphanumeric(12)
      user = Msf::MCP::Config::Defaults::RPC_USER
      host = opts['RpcHost'] || Msf::MCP::Config::Defaults::RPC_HOST
      port = opts['RpcPort'] || Msf::MCP::Config::Defaults::MSGRPC_PORT
      ssl_bool = parse_bool(opts['RpcSSL'], default: Msf::MCP::Config::Defaults::RPC_SSL)

      msgrpc_opts = {
        'Pass' => pass,
        'User' => user,
        'ServerHost' => host,
        'ServerPort' => port,
        'SSL' => ssl_bool.to_s
      }

      framework.plugins.load('msgrpc', msgrpc_opts)
      @auto_started_rpc = true

      # Confirm the server actually bound before claiming success
      verify_msgrpc_started!(host, port)

      print_status("Auto-started msgrpc - User: #{user}, Pass: #{pass}")

      {
        host: host,
        port: Integer(port),
        user: user,
        pass: pass,
        ssl: ssl_bool
      }
    end

    # Polls TCP port until reachable or timeout. Raises with service_name in message.
    def wait_for_port!(host, port, service_name, timeout: 5)
      print_status("Waiting for #{service_name} to become available on #{Rex::Socket.to_authority(host, port.to_s)}...")
      result = poll_until_truthy(timeout: timeout, interval: 0.25) do
        sock = Rex::Socket::Tcp.create('PeerHost' => host, 'PeerPort' => port.to_i, 'Timeout' => 1)
        sock.close
        true
      rescue ::Rex::ConnectionRefused, ::Rex::ConnectionTimeout, ::Errno::ECONNREFUSED
        nil
      end

      return if result

      raise Msf::MCP::Error,
            "#{service_name} failed to start on #{Rex::Socket.to_authority(host, port.to_s)} (port may already be in use)"
    end

    # Pre-flight check: catch EADDRINUSE synchronously before spawning async server thread
    def verify_port_available!(host, port)
      test_server = TCPServer.new(host, port.to_i)
      test_server.close
    rescue Errno::EADDRINUSE
      raise Msf::MCP::Error, "Address already in use: #{Rex::Socket.to_authority(host, port.to_s)}"
    rescue Errno::EADDRNOTAVAIL
      raise Msf::MCP::Error, "Address not available: #{Rex::Socket.to_authority(host, port.to_s)}"
    end

    # Confirms msgrpc plugin loaded and its server is listening
    def verify_msgrpc_started!(host, port, timeout: 5)
      msgrpc = framework.plugins.find { |p| p.name == 'msgrpc' }
      unless msgrpc
        raise Msf::MCP::Error, 'msgrpc plugin failed to load'
      end

      # Wait for server object to initialize
      print_status("Waiting for msgrpc server to initialize on #{Rex::Socket.to_authority(host, port.to_s)}...")
      poll_until_truthy(timeout: timeout, interval: 0.25) do
        msgrpc.respond_to?(:server) && msgrpc.server
      end

      unless msgrpc.server
        raise Msf::MCP::Error,
              "msgrpc server failed to start on #{Rex::Socket.to_authority(host, port.to_s)} (port may already be in use)"
      end

      wait_for_port!(host, port, 'msgrpc server', timeout: timeout)
    end

    # Confirms MCP server is listening after thread spawn
    def verify_mcp_server_started!(host, port, timeout: 5)
      wait_for_port!(host, port, 'MCP server', timeout: timeout)
    end

    def option_error(option_name, expected_format)
      error_detail = "Invalid value for #{option_name}: expected #{expected_format}"
      raise Msf::MCP::Config::ValidationError, { option_name => error_detail }
    end

    # Case-insensitive boolean-string parser. Returns +default+ when +value+ is nil.
    def parse_bool(value, default:)
      return default if value.nil?

      value.to_s.casecmp?('true')
    end

  end
end
