# frozen_string_literal: true

require 'securerandom'
require 'socket'

module Msf::MCP
  # Manages the lifecycle of a Metasploit RPC server process.
  #
  # Probes the configured RPC port, auto-starts the server via Process.spawn
  # of msfrpcd, and cleans up the child process on shutdown.
  class RpcManager
    LOCALHOST_HOSTS = %w[localhost 127.0.0.1 ::1].freeze
    DEFAULT_WAIT_TIMEOUT = 30
    DEFAULT_WAIT_INTERVAL = 1
    STOP_GRACE_PERIOD = 5

    attr_reader :rpc_pid

    # @param config [Hash] Application configuration hash
    # @param output [IO] Output stream for status messages
    def initialize(config:, output:)
      @config = config
      @output = output
      @rpc_pid = nil
      @rpc_managed = false
    end

    # Whether this manager started and is managing an RPC server process.
    #
    # @return [Boolean]
    def rpc_managed?
      @rpc_managed
    end

    # Probe the configured RPC port to check if a server is listening.
    #
    # @return [Boolean]
    def rpc_available?
      host = @config[:msf_api][:host]
      port = @config[:msf_api][:port]

      socket = Rex::Socket::Tcp.create(
        'PeerHost' => host,
        'PeerPort' => port
      )
      socket.close
      dlog({ message: "RPC server is available at #{Rex::Socket.to_authority(host, port)}" },
           LOG_SOURCE, LOG_DEBUG)
      true
    rescue Rex::ConnectionError
      false
    end

    # Whether auto-start is enabled based on config, API type, and host.
    #
    # Auto-start is only supported for:
    # - MessagePack API type (not JSON-RPC)
    # - Localhost connections (cannot start a remote RPC server)
    # - When auto_start_rpc config is not explicitly false
    #
    # @return [Boolean]
    def auto_start_enabled?
      return false if @config[:msf_api][:type] != 'messagepack'
      return false unless localhost?
      return false if @config[:msf_api][:auto_start_rpc] == false

      true
    end

    # Start the Metasploit RPC server by spawning msfrpcd.
    #
    # Credentials are passed via environment variables to avoid exposing
    # them on the command line.
    #
    # @return [void]
    # @raise [Msf::MCP::Metasploit::RpcStartupError] If the server cannot be started
    def start_rpc_server
      if @rpc_managed
        @output.puts 'RPC server is already managed by this process'
        return
      end

      @output.puts 'Starting Metasploit RPC server...'
      ilog({ message: 'Starting Metasploit RPC server' },
           LOG_SOURCE, LOG_INFO)

      unless File.executable?(MSFRPCD_PATH)
        raise Msf::MCP::Metasploit::RpcStartupError,
              'msfrpcd executable not found. Cannot auto-start RPC server.'
      end

      args = build_msfrpcd_args
      env = {
        'MSF_RPC_USER' => @config[:msf_api][:user].to_s,
        'MSF_RPC_PASS' => @config[:msf_api][:password].to_s
      }

      pid = Process.spawn(env, MSFRPCD_PATH, *args, %i[out err] => File::NULL)

      @rpc_pid = pid
      @rpc_managed = true
      @output.puts "RPC server started via msfrpcd (PID: #{pid})"
    end

    # Wait for the RPC server to become available.
    #
    # @param timeout [Integer] Maximum seconds to wait (default: 30)
    # @param interval [Integer] Seconds between probes (default: 1)
    # @return [true] When the server becomes available
    # @raise [Msf::MCP::Metasploit::ConnectionError] If timeout is reached
    # @raise [Msf::MCP::Metasploit::RpcStartupError] If the managed process exits
    def wait_for_rpc(timeout: DEFAULT_WAIT_TIMEOUT, interval: DEFAULT_WAIT_INTERVAL)
      deadline = Time.now + timeout

      loop do
        if rpc_available?
          @output.puts 'RPC server is ready'
          return true
        end

        check_managed_process_alive! if @rpc_managed

        if Time.now >= deadline
          raise Msf::MCP::Metasploit::ConnectionError,
                "Timed out waiting for RPC server after #{timeout} seconds"
        end

        @output.puts 'Waiting for RPC server to become available...'
        sleep(interval)
      end
    end

    # Stop the managed RPC server process.
    #
    # @return [void]
    def stop_rpc_server
      return unless @rpc_managed

      @output.puts 'Stopping managed RPC server...'
      ilog({ message: "Stopping managed RPC server (PID: #{@rpc_pid})" },
           LOG_SOURCE, LOG_INFO)

      begin
        Process.kill('TERM', @rpc_pid)
        graceful_wait
      rescue Errno::ESRCH
        # Process already dead — that's fine
      rescue Errno::EPERM
        @output.puts "Warning: no permission to stop RPC process #{@rpc_pid}"
      end

      @rpc_pid = nil
      @rpc_managed = false
    end

    # Ensure an RPC server is available, auto-starting if needed.
    #
    # When the RPC server is already listening, verifies that credentials
    # (or a token for JSON-RPC) are available for the caller to authenticate.
    #
    # When the server is not available, auto-start is attempted only for
    # MessagePack on localhost with auto_start_rpc enabled.  Random
    # credentials are generated when none are provided.
    #
    # @return [void]
    # @raise [Msf::MCP::Metasploit::RpcStartupError] If the server cannot be
    #   reached and auto-start is not possible, or if the server is running
    #   but no credentials/token were provided
    def ensure_rpc_available
      if rpc_available?
        @output.puts 'Metasploit RPC server is already running'
        validate_credentials_for_existing_server!
        return
      end

      if @config[:msf_api][:type] == 'json-rpc'
        raise Msf::MCP::Metasploit::RpcStartupError,
              'RPC server is not running and auto-start is not supported for JSON-RPC API type.'
      end

      unless localhost?
        message = "RPC server is not available at #{@config[:msf_api][:host]}:#{@config[:msf_api][:port]}."
        message << ' Cannot auto-start RPC on remote hosts. Please start the RPC server manually.' if auto_start_enabled?
        raise Msf::MCP::Metasploit::RpcStartupError, message
      end

      unless auto_start_enabled?
        raise Msf::MCP::Metasploit::RpcStartupError,
              "RPC server is not running on #{@config[:msf_api][:host]}:#{@config[:msf_api][:port]} " \
              'and auto-start is disabled.'
      end

      generate_random_credentials unless credentials_provided?
      start_rpc_server
      wait_for_rpc
    end

    private

    # Absolute path to msfrpcd relative to the framework root.
    MSFRPCD_PATH = File.join(__dir__, '../../../..', 'msfrpcd').freeze

    # Build command-line arguments for msfrpcd.
    #
    # Note: credentials are passed via environment variables (MSF_RPC_USER,
    # MSF_RPC_PASS) rather than command-line arguments for security.
    #
    # @return [Array<String>]
    def build_msfrpcd_args
      args = ['-f'] # foreground mode
      args.push('-a', @config[:msf_api][:host].to_s)
      args.push('-p', @config[:msf_api][:port].to_s)
      args.push('-S') if @config[:msf_api][:ssl] == false
      args
    end

    # Check whether the host is a localhost address.
    #
    # @return [Boolean]
    def localhost?
      LOCALHOST_HOSTS.include?(@config[:msf_api][:host].to_s.downcase)
    end

    # Whether both user and password are present in the configuration.
    #
    # @return [Boolean]
    def credentials_provided?
      user = @config[:msf_api][:user]
      password = @config[:msf_api][:password]
      !user.to_s.strip.empty? && !password.to_s.strip.empty?
    end

    # Whether the BEARER token is present in the configuration.
    #
    # @return [Boolean]
    def token_provided?
      token = @config[:msf_api][:token]
      !token.to_s.strip.empty?
    end

    # Verify that the caller has credentials to authenticate with an
    # already-running RPC server.  For MessagePack this means user+password;
    # for JSON-RPC this means a bearer token.
    #
    # @raise [Msf::MCP::Metasploit::RpcStartupError] If required credentials
    #   are missing
    def validate_credentials_for_existing_server!
      if @config[:msf_api][:type] == 'json-rpc'
        return if token_provided?

        raise Msf::MCP::Metasploit::RpcStartupError,
              'RPC server is already running but no token was provided. ' \
              'Use --token option or MSF_API_TOKEN environment variable.'
      else
        return if credentials_provided?

        raise Msf::MCP::Metasploit::RpcStartupError,
              'RPC server is already running but no credentials were provided. ' \
              'Use --user and --password options or MSF_API_USER and MSF_API_PASSWORD environment variables.'
      end
    end

    # Generate random credentials and write them into the config hash.
    #
    # @return [void]
    def generate_random_credentials
      @config[:msf_api][:user] = SecureRandom.hex(8)
      @config[:msf_api][:password] = SecureRandom.hex(16)
      @output.puts 'Generated random credentials for auto-started RPC server'
      ilog({ message: 'Generated random credentials for auto-started RPC server' },
           LOG_SOURCE, LOG_INFO)
    end

    # Check if the managed child process is still alive.
    # Raises RpcStartupError if it has exited.
    def check_managed_process_alive!
      return unless @rpc_pid

      result = Process.waitpid(@rpc_pid, Process::WNOHANG)
      return unless result

      @rpc_pid = nil
      @rpc_managed = false
      raise Msf::MCP::Metasploit::RpcStartupError, 'RPC server process exited unexpectedly'
    end

    # Wait for the child process to exit after SIGTERM, escalating to
    # SIGKILL if it does not exit within the grace period.
    def graceful_wait
      result = Process.waitpid(@rpc_pid, Process::WNOHANG)
      return if result

      sleep(STOP_GRACE_PERIOD)
      result = Process.waitpid(@rpc_pid, Process::WNOHANG)
      return if result

      # Process did not exit; escalate to SIGKILL
      Process.kill('KILL', @rpc_pid)
      Process.waitpid(@rpc_pid, 0)
    end
  end
end
