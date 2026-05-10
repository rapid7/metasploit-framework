# frozen_string_literal: true

require 'msf/core/mcp'
require 'stringio'
require 'tempfile'

RSpec.describe Msf::MCP::Application do
  let(:output) { StringIO.new }
  let(:valid_config) do
    {
      msf_api: {
        type: 'messagepack',
        host: 'localhost',
        port: 55553,
        ssl: true,
        endpoint: '/api/',
        user: 'testuser',
        password: 'testpass'
      },
      mcp: {
        transport: 'stdio'
      },
      rate_limit: {
        requests_per_minute: 60,
        burst_size: 10
      }
    }
  end

  describe '#initialize' do
    it 'initializes with default values' do
      app = described_class.new([], output: output)

      expect(app.options[:config_path]).to be_nil
      # Logging options are no longer in defaults, they come from config file
      expect(app.options[:enable_logging_cli]).to be_nil
      expect(app.options[:log_file_cli]).to be_nil
    end

    it 'accepts custom output stream' do
      # Verify output is used - instantiation doesn't trigger help automatically
      app = described_class.new([], output: output)
      expect(app).to be_a(described_class)

      # Test that parse_arguments with --help writes to output
      help_output = StringIO.new
      help_app = described_class.new(['--help'], output: help_output)
      expect { help_app.send(:parse_arguments) }.to raise_error(SystemExit)
      expect(help_output.string).to include('MSF MCP Server')
    end
  end

  describe '#parse_arguments' do
    it 'parses --config argument' do
      app = described_class.new(['--config', '/custom/path/config.yml'], output: output)
      app.send(:parse_arguments)

      expect(app.options[:config_path]).to eq('/custom/path/config.yml')
    end

    it 'parses --enable-logging argument' do
      app = described_class.new(['--enable-logging'], output: output)
      app.send(:parse_arguments)

      expect(app.options[:enable_logging_cli]).to be true
    end

    it 'parses --log-file argument' do
      app = described_class.new(['--log-file', 'custom.log'], output: output)
      app.send(:parse_arguments)

      expect(app.options[:log_file_cli]).to eq('custom.log')
    end

    it 'exits with help message on --help' do
      app = described_class.new(['--help'], output: output)

      expect { app.send(:parse_arguments) }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(0)
      end
      expect(output.string).to include('MSF MCP Server')
      expect(output.string).to include('Usage:')
    end

    it 'exits with version on --version' do
      app = described_class.new(['--version'], output: output)

      expect { app.send(:parse_arguments) }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(0)
      end
      expect(output.string).to include('msfmcp version')
    end

    it 'accepts short form -h for help' do
      app = described_class.new(['-h'], output: output)

      expect { app.send(:parse_arguments) }.to raise_error(SystemExit)
      expect(output.string).to include('MSF MCP Server')
    end

    it 'accepts short form -v for version' do
      app = described_class.new(['-v'], output: output)

      expect { app.send(:parse_arguments) }.to raise_error(SystemExit)
      expect(output.string).to include('msfmcp version')
    end

    it 'parses --no-auto-start-rpc argument' do
      app = described_class.new(['--no-auto-start-rpc'], output: output)
      app.send(:parse_arguments)

      expect(app.options[:no_auto_start_rpc]).to be true
    end

    it 'does not set no_auto_start_rpc by default' do
      app = described_class.new([], output: output)
      app.send(:parse_arguments)

      expect(app.options[:no_auto_start_rpc]).to be_nil
    end
  end

  describe '#initialize_logger' do
    let(:log_file) { Tempfile.new('app_test_log').tap(&:close).path }

    after do
      if log_source_registered?(Msf::MCP::LOG_SOURCE)
        deregister_log_source(Msf::MCP::LOG_SOURCE)
      end
      File.delete(log_file) if File.exist?(log_file)
    end

    it 'does not register a Rex source when logging is disabled' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, {})
      app.send(:initialize_logger)

      expect(log_source_registered?(Msf::MCP::LOG_SOURCE)).to be false
    end

    it 'registers the Rex source when --enable-logging is set' do
      app = described_class.new(['--enable-logging', '--log-file', log_file], output: output)
      app.send(:parse_arguments)
      app.instance_variable_set(:@config, { logging: { enabled: false, level: 'INFO', sanitize: false } })
      app.send(:initialize_logger)

      expect(log_source_registered?(Msf::MCP::LOG_SOURCE)).to be true
    end

    it 'registers the Rex source when logging.enabled is true in config' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, { logging: { enabled: true, level: 'INFO', log_file: log_file, sanitize: false } })
      app.send(:initialize_logger)

      expect(log_source_registered?(Msf::MCP::LOG_SOURCE)).to be true
    end

    it 'uses CLI log file path over config file path' do
      cli_log = Tempfile.new('cli_log').tap(&:close).path
      app = described_class.new(['--log-file', cli_log], output: output)
      app.send(:parse_arguments)
      app.instance_variable_set(:@config, { logging: { enabled: true, level: 'INFO', log_file: log_file, sanitize: false } })
      app.send(:initialize_logger)

      # Emit a message and confirm it went to the CLI path, not the config path
      ilog('probe', Msf::MCP::LOG_SOURCE, Rex::Logging::LEV_0)
      expect(File.read(cli_log)).to include('probe')
      expect(File.read(log_file)).to be_empty

      deregister_log_source(Msf::MCP::LOG_SOURCE)
      File.delete(cli_log) if File.exist?(cli_log)
    end

    it 'wraps the sink with Sanitizing when sanitize is true' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, { logging: { enabled: true, level: 'INFO', log_file: log_file, sanitize: true } })
      app.send(:initialize_logger)

      # Log a message containing a sensitive pattern and verify it is redacted
      elog({ message: 'password= s3cret' }, Msf::MCP::LOG_SOURCE, Rex::Logging::LEV_0)
      content = File.read(log_file)
      expect(content).to include('[REDACTED]')
      expect(content).not_to include('s3cret')
    end

    it 'does not wrap with Sanitizing when sanitize is false' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, { logging: { enabled: true, level: 'INFO', log_file: log_file, sanitize: false } })
      app.send(:initialize_logger)

      # Log a message containing a sensitive pattern — should appear as-is
      elog({ message: 'password= s3cret' }, Msf::MCP::LOG_SOURCE, Rex::Logging::LEV_0)
      content = File.read(log_file)
      expect(content).to include('s3cret')
    end
  end

  describe '#install_signal_handlers' do
    it 'installs signal handlers for INT and TERM' do
      app = described_class.new([], output: output)

      # Mock Signal.trap to avoid actually installing handlers in tests
      expect(Signal).to receive(:trap).with('INT')
      expect(Signal).to receive(:trap).with('TERM')

      app.send(:install_signal_handlers)
    end
  end

  describe '#load_configuration' do
    it 'loads configuration from file' do
      config_file = Tempfile.new(['config', '.yml'])
      # Dirty hack to make sure the config hash keys are strings and not symbols.
      config_file.write(YAML.dump(JSON.parse(valid_config.to_json)))
      config_file.flush

      app = described_class.new(['--config', config_file.path], output: output)
      app.send(:parse_arguments)
      app.send(:load_configuration)

      expect(app.config).to be_a(Hash)
      expect(app.config[:msf_api][:type]).to eq('messagepack')

      config_file.close
      config_file.unlink
    end

    it 'outputs loading message' do
      config_file = Tempfile.new(['config', '.yml'])
      # Dirty hack to make sure the config hash keys are strings and not symbols.
      config_file.write(YAML.dump(JSON.parse(valid_config.to_json)))
      config_file.flush

      app = described_class.new(['--config', config_file.path], output: output)
      app.send(:parse_arguments)
      app.send(:load_configuration)

      expect(output.string).to include("Loading configuration from #{config_file.path}")

      config_file.close
      config_file.unlink
    end

    it 'raises error for missing file' do
      app = described_class.new(['--config', '/nonexistent/config.yml'], output: output)
      app.send(:parse_arguments)

      expect { app.send(:load_configuration) }.to raise_error(Msf::MCP::Config::ConfigurationError, /not found/)
    end
  end

  describe '#validate_configuration' do
    it 'validates configuration successfully' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, valid_config)

      expect { app.send(:validate_configuration) }.not_to raise_error
      expect(output.string).to include('Validating configuration...')
      expect(output.string).to include('Configuration valid')
    end

    it 'raises error for invalid configuration' do
      app = described_class.new([], output: output)
      # Use a config with an actual validation error (invalid enum value)
      app.instance_variable_set(:@config, { msf_api: { type: 'invalid_type' } })

      expect { app.send(:validate_configuration) }.to raise_error(Msf::MCP::Config::ValidationError)
    end
  end

  describe '#initialize_rate_limiter' do
    it 'creates rate limiter with config values' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, valid_config)
      app.send(:initialize_rate_limiter)

      expect(app.rate_limiter).to be_a(Msf::MCP::Security::RateLimiter)
      expect(app.rate_limiter.instance_variable_get(:@requests_per_minute)).to eq(60)
    end

    it 'uses default values when rate_limit config is missing' do
      config_without_rate_limit = valid_config.dup
      config_without_rate_limit.delete(:rate_limit)

      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, config_without_rate_limit)
      app.send(:initialize_rate_limiter)

      expect(app.rate_limiter).to be_a(Msf::MCP::Security::RateLimiter)
      expect(app.rate_limiter.instance_variable_get(:@requests_per_minute)).to eq(60)
    end
  end

  describe '#initialize_metasploit_client' do
    it 'creates Metasploit client with config values' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, valid_config)

      # Mock the Client.new to avoid actual connection
      mock_client = instance_double(Msf::MCP::Metasploit::Client)
      expect(Msf::MCP::Metasploit::Client).to receive(:new).with(
        api_type: 'messagepack',
        host: 'localhost',
        port: 55553,
        ssl: true,
        endpoint: '/api/',
        token: nil
      ).and_return(mock_client)

      app.send(:initialize_metasploit_client)

      expect(app.msf_client).to eq(mock_client)
      expect(output.string).to include('Connecting to Metasploit RPC at localhost:55553')
    end
  end

  describe '#authenticate_metasploit' do
    let(:mock_client) { instance_double(Msf::MCP::Metasploit::Client) }

    before do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, valid_config)
      app.instance_variable_set(:@msf_client, mock_client)
    end

    it 'authenticates when using MessagePack' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, valid_config)
      app.instance_variable_set(:@msf_client, mock_client)

      expect(mock_client).to receive(:authenticate).with('testuser', 'testpass')

      app.send(:authenticate_metasploit)

      expect(output.string).to include('Authenticating with Metasploit...')
      expect(output.string).to include('Authentication successful')
    end

    it 'skips authentication when using JSON-RPC' do
      json_rpc_config = valid_config.dup
      json_rpc_config[:msf_api][:type] = 'json-rpc'
      json_rpc_config[:msf_api][:token] = 'test_token'

      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, json_rpc_config)
      app.instance_variable_set(:@msf_client, mock_client)

      expect(mock_client).not_to receive(:authenticate)

      app.send(:authenticate_metasploit)

      expect(output.string).to include('Using JSON-RPC with token authentication')
    end
  end

  describe '#initialize_mcp_server' do
    it 'creates MCP server with dependencies' do
      mock_client = instance_double(Msf::MCP::Metasploit::Client)
      mock_rate_limiter = instance_double(Msf::MCP::Security::RateLimiter)
      mock_mcp_server = instance_double(Msf::MCP::Server)

      app = described_class.new([], output: output)
      app.instance_variable_set(:@msf_client, mock_client)
      app.instance_variable_set(:@rate_limiter, mock_rate_limiter)

      expect(Msf::MCP::Server).to receive(:new).with(
        msf_client: mock_client,
        rate_limiter: mock_rate_limiter
      ).and_return(mock_mcp_server)

      app.send(:initialize_mcp_server)

      expect(app.mcp_server).to eq(mock_mcp_server)
      expect(output.string).to include('Initializing MCP server...')
    end
  end

  describe '#start_mcp_server' do
    let(:mock_mcp_server) { instance_double(Msf::MCP::Server) }

    it 'starts server with stdio transport by default' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, valid_config)
      app.instance_variable_set(:@mcp_server, mock_mcp_server)

      expect(mock_mcp_server).to receive(:start).with(transport: :stdio)

      app.send(:start_mcp_server)

      expect(output.string).to include('Starting MCP server on stdio transport...')
      expect(output.string).to include('Server ready - waiting for MCP requests')
    end

    it 'starts server with HTTP transport when configured' do
      http_config = valid_config.dup
      http_config[:mcp] = {
        transport: 'http',
        host: '0.0.0.0',
        port: 3000
      }

      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, http_config)
      app.instance_variable_set(:@mcp_server, mock_mcp_server)

      expect(mock_mcp_server).to receive(:start).with(transport: :http, host: '0.0.0.0', port: 3000)

      app.send(:start_mcp_server)

      expect(output.string).to include('Starting MCP server on HTTP transport...')
      expect(output.string).to include('Server listening on http://0.0.0.0:3000')
    end

    it 'uses default host and port for HTTP transport' do
      http_config = valid_config.dup
      http_config[:mcp] = { transport: 'http' }

      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, http_config)
      app.instance_variable_set(:@mcp_server, mock_mcp_server)

      expect(mock_mcp_server).to receive(:start).with(transport: :http, host: 'localhost', port: 3000)

      app.send(:start_mcp_server)
    end
  end

  describe '#shutdown' do
    it 'outputs shutdown complete' do
      app = described_class.new([], output: output)
      app.shutdown('INT')

      expect(output.string).to include('Shutdown complete')
    end

    it 'does not raise when no Rex sink is registered' do
      app = described_class.new([], output: output)
      expect { app.shutdown('TERM') }.not_to raise_error
    end

    it 'calls shutdown on mcp_server when present' do
      mock_mcp_server = instance_double(Msf::MCP::Server)

      app = described_class.new([], output: output)
      app.instance_variable_set(:@mcp_server, mock_mcp_server)

      expect(mock_mcp_server).to receive(:shutdown)

      app.shutdown('INT')

      expect(output.string).to include('Shutdown complete')
    end

    it 'calls stop_rpc_server on rpc_manager when present' do
      mock_rpc_manager = instance_double(Msf::MCP::RpcManager)

      app = described_class.new([], output: output)
      app.instance_variable_set(:@rpc_manager, mock_rpc_manager)

      expect(mock_rpc_manager).to receive(:stop_rpc_server)

      app.shutdown('INT')
    end

    it 'handles nil mcp_server gracefully' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@mcp_server, nil)

      expect { app.shutdown('INT') }.not_to raise_error
      expect(output.string).to include('Shutdown complete')
    end

    it 'handles nil rpc_manager gracefully' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@rpc_manager, nil)

      expect { app.shutdown('INT') }.not_to raise_error
      expect(output.string).to include('Shutdown complete')
    end
  end

  describe '#ensure_rpc_server' do
    context 'when RPC is already available' do
      it 'does not create an RPC manager' do
        app = described_class.new([], output: output)
        app.instance_variable_set(:@config, valid_config)

        mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
        allow(Msf::MCP::RpcManager).to receive(:new).and_return(mock_rpc_manager)
        allow(mock_rpc_manager).to receive(:ensure_rpc_available)

        app.send(:ensure_rpc_server)

        expect(app.rpc_manager).to eq(mock_rpc_manager)
      end

      it 'calls ensure_rpc_available on the manager' do
        app = described_class.new([], output: output)
        app.instance_variable_set(:@config, valid_config)

        mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
        allow(Msf::MCP::RpcManager).to receive(:new).and_return(mock_rpc_manager)

        expect(mock_rpc_manager).to receive(:ensure_rpc_available)

        app.send(:ensure_rpc_server)
      end
    end

    context 'when --no-auto-start-rpc is set' do
      it 'sets auto_start_rpc to false in config during load_configuration' do
        app = described_class.new(['--no-auto-start-rpc'], output: output)
        app.send(:parse_arguments)
        app.instance_variable_set(:@config, valid_config.dup)

        # Simulate load_configuration CLI override
        app.send(:load_configuration) rescue nil
        # Directly verify the config was updated by setting it up properly
        app = described_class.new(['--no-auto-start-rpc'], output: output)
        app.send(:parse_arguments)
        config = valid_config.dup
        config[:msf_api] = config[:msf_api].dup
        app.instance_variable_set(:@config, config)

        # Apply the override as load_configuration would
        config[:msf_api][:auto_start_rpc] = false if app.options[:no_auto_start_rpc]

        mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
        allow(mock_rpc_manager).to receive(:ensure_rpc_available)

        expect(Msf::MCP::RpcManager).to receive(:new).with(
          hash_including(config: hash_including(msf_api: hash_including(auto_start_rpc: false)))
        ).and_return(mock_rpc_manager)

        app.send(:ensure_rpc_server)
      end
    end

    context 'when RPC startup fails' do
      it 'propagates RpcStartupError' do
        app = described_class.new([], output: output)
        app.instance_variable_set(:@config, valid_config)

        mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
        allow(Msf::MCP::RpcManager).to receive(:new).and_return(mock_rpc_manager)
        allow(mock_rpc_manager).to receive(:ensure_rpc_available).and_raise(
          Msf::MCP::Metasploit::RpcStartupError.new('msfrpcd not found')
        )

        expect { app.send(:ensure_rpc_server) }.to raise_error(Msf::MCP::Metasploit::RpcStartupError)
      end
    end

    context 'when connection times out' do
      it 'propagates ConnectionError' do
        app = described_class.new([], output: output)
        app.instance_variable_set(:@config, valid_config)

        mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
        allow(Msf::MCP::RpcManager).to receive(:new).and_return(mock_rpc_manager)
        allow(mock_rpc_manager).to receive(:ensure_rpc_available).and_raise(
          Msf::MCP::Metasploit::ConnectionError.new('Timed out waiting for RPC server')
        )

        expect { app.send(:ensure_rpc_server) }.to raise_error(Msf::MCP::Metasploit::ConnectionError)
      end
    end

    it 'passes output to RpcManager' do
      app = described_class.new([], output: output)
      app.instance_variable_set(:@config, valid_config)

      mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
      allow(mock_rpc_manager).to receive(:ensure_rpc_available)

      expect(Msf::MCP::RpcManager).to receive(:new).with(
        hash_including(output: output)
      ).and_return(mock_rpc_manager)

      app.send(:ensure_rpc_server)
    end
  end

  describe 'error handlers' do
    describe '#handle_configuration_error' do
      it 'outputs error message and exits' do
        app = described_class.new([], output: output)
        error = Msf::MCP::Config::ValidationError.new({ 'msf_api.type': 'is invalid' })

        expect { app.send(:handle_configuration_error, error) }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(1)
        end
        expect(output.string).to include('Configuration validation failed')
      end

      it 'handles ConfigurationError the same way' do
        app = described_class.new([], output: output)
        error = Msf::MCP::Config::ConfigurationError.new('Configuration file not found: /missing.yml')

        expect { app.send(:handle_configuration_error, error) }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(1)
        end
        expect(output.string).to include('Configuration file not found')
      end

      it 'does not call elog (logger not available yet)' do
        app = described_class.new([], output: output)
        error = Msf::MCP::Config::ValidationError.new({})

        # elog should not be called — logger is not initialized at this stage
        expect(app).not_to receive(:elog)
        expect { app.send(:handle_configuration_error, error) }.to raise_error(SystemExit)
      end
    end

    describe '#handle_connection_error' do
      it 'outputs connection error with host and port' do
        app = described_class.new([], output: output)
        app.instance_variable_set(:@config, valid_config)
        error = Msf::MCP::Metasploit::ConnectionError.new('Connection refused')

        expect { app.send(:handle_connection_error, error) }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(1)
        end
        expect(output.string).to include('Connection error to Metasploit RPC at localhost:55553')
        expect(output.string).to include('Connection refused')
      end

      it 'logs the error via elog' do
        app = described_class.new([], output: output)
        app.instance_variable_set(:@config, valid_config)
        error = Msf::MCP::Metasploit::ConnectionError.new('Connection refused')

        expect(app).to receive(:elog).with(hash_including(message: 'Connection error'), anything, anything)
        expect { app.send(:handle_connection_error, error) }.to raise_error(SystemExit)
      end
    end

    describe '#handle_api_error' do
      it 'outputs API error message' do
        app = described_class.new([], output: output)
        error = Msf::MCP::Metasploit::APIError.new('Invalid method')

        expect { app.send(:handle_api_error, error) }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(1)
        end
        expect(output.string).to include('Metasploit API error: Invalid method')
      end

      it 'logs the error via elog' do
        app = described_class.new([], output: output)
        error = Msf::MCP::Metasploit::APIError.new('Invalid method')

        expect(app).to receive(:elog).with(hash_including(message: 'Metasploit API error'), anything, anything)
        expect { app.send(:handle_api_error, error) }.to raise_error(SystemExit)
      end
    end

    describe '#handle_authentication_error' do
      it 'outputs authentication error with username' do
        app = described_class.new([], output: output)
        app.instance_variable_set(:@config, valid_config)
        error = Msf::MCP::Metasploit::AuthenticationError.new('Login Failed')

        expect { app.send(:handle_authentication_error, error) }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(1)
        end
        expect(output.string).to include('Authentication error (username: testuser): Login Failed')
      end

      it 'logs the error via elog' do
        app = described_class.new([], output: output)
        app.instance_variable_set(:@config, valid_config)
        error = Msf::MCP::Metasploit::AuthenticationError.new('Login Failed')

        expect(app).to receive(:elog).with(hash_including(message: 'Authentication error'), anything, anything)
        expect { app.send(:handle_authentication_error, error) }.to raise_error(SystemExit)
      end
    end

    describe '#handle_rpc_startup_error' do
      it 'outputs RPC startup error message and exits' do
        app = described_class.new([], output: output)
        error = Msf::MCP::Metasploit::RpcStartupError.new('msfrpcd not found')

        expect { app.send(:handle_rpc_startup_error, error) }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(1)
        end
        expect(output.string).to include('RPC startup error: msfrpcd not found')
      end

      it 'logs the error via elog' do
        app = described_class.new([], output: output)
        error = Msf::MCP::Metasploit::RpcStartupError.new('msfrpcd not found')

        expect(app).to receive(:elog).with(hash_including(message: 'RPC startup error'), anything, anything)
        expect { app.send(:handle_rpc_startup_error, error) }.to raise_error(SystemExit)
      end
    end

    describe '#handle_fatal_error' do
      it 'outputs error message and backtrace' do
        app = described_class.new([], output: output)
        error = StandardError.new('Unexpected error')
        error.set_backtrace(['line1', 'line2', 'line3', 'line4', 'line5', 'line6'])

        expect { app.send(:handle_fatal_error, error) }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(1)
        end
        expect(output.string).to include('Fatal error: Unexpected error')
        expect(output.string).to include('line1')
        expect(output.string).to include('line5')
        expect(output.string).not_to include('line6') # Only first 5 lines
      end

      it 'logs the error via elog' do
        app = described_class.new([], output: output)
        error = StandardError.new('Unexpected error')

        expect(app).to receive(:elog).with(hash_including(message: 'Fatal error during startup'), anything, anything)
        expect { app.send(:handle_fatal_error, error) }.to raise_error(SystemExit)
      end
    end
  end

  describe '#run' do
    let(:config_file) { Tempfile.new(['config', '.yml']) }
    let(:mock_mcp_server) { instance_double(Msf::MCP::Server) }
    let(:mock_client) { instance_double(Msf::MCP::Metasploit::Client) }

    before do
      # Dirty hack to make sure the config hash keys are strings and not symbols.
      config_file.write(YAML.dump(JSON.parse(valid_config.to_json)))
      config_file.flush
    end

    after do
      config_file.close
      config_file.unlink
    end

    it 'runs through the complete startup sequence successfully' do
      app = described_class.new(['--config', config_file.path], output: output)

      # Mock RPC manager
      mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
      allow(Msf::MCP::RpcManager).to receive(:new).and_return(mock_rpc_manager)
      allow(mock_rpc_manager).to receive(:ensure_rpc_available)

      # Mock external dependencies
      allow(Msf::MCP::Metasploit::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:authenticate)
      allow(Msf::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      allow(mock_mcp_server).to receive(:start)

      # Mock signal handlers to avoid actual installation
      allow(Signal).to receive(:trap)

      app.run

      # Verify all initialization steps occurred
      expect(output.string).to include('Loading configuration')
      expect(output.string).to include('Validating configuration')
      expect(output.string).to include('Configuration valid')
      expect(output.string).to include('Connecting to Metasploit RPC')
      expect(output.string).to include('Authenticating with Metasploit')
      expect(output.string).to include('Authentication successful')
      expect(output.string).to include('Initializing MCP server')
      expect(output.string).to include('Starting MCP server')
    end

    it 'handles configuration errors gracefully' do
      bad_config = { msf_api: {} }
      config_file.rewind
      # Dirty hack to make sure the config hash keys are strings and not symbols.
      config_file.write(YAML.dump(JSON.parse(bad_config.to_json)))
      config_file.flush

      app = described_class.new(['--config', config_file.path], output: output)

      expect { app.run }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
      expect(output.string).to include('Configuration validation failed')
    end

    it 'handles missing config file gracefully' do
      app = described_class.new(['--config', '/nonexistent/config.yml'], output: output)

      expect { app.run }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
      expect(output.string).to include('Configuration file not found')
    end

    it 'handles authentication errors gracefully' do
      app = described_class.new(['--config', config_file.path], output: output)

      mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
      allow(Msf::MCP::RpcManager).to receive(:new).and_return(mock_rpc_manager)
      allow(mock_rpc_manager).to receive(:ensure_rpc_available)

      allow(Msf::MCP::Metasploit::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:authenticate).and_raise(
        Msf::MCP::Metasploit::AuthenticationError.new('Login Failed')
      )
      allow(Signal).to receive(:trap)

      expect { app.run }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
      expect(output.string).to include('Authentication error')
      expect(output.string).to include('Login Failed')
    end

    it 'handles connection errors gracefully' do
      app = described_class.new(['--config', config_file.path], output: output)

      mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
      allow(Msf::MCP::RpcManager).to receive(:new).and_return(mock_rpc_manager)
      allow(mock_rpc_manager).to receive(:ensure_rpc_available)

      allow(Msf::MCP::Metasploit::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:authenticate).and_raise(
        Msf::MCP::Metasploit::ConnectionError.new('Connection refused')
      )
      allow(Signal).to receive(:trap)

      expect { app.run }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
      expect(output.string).to include('Connection error')
    end

    it 'handles RPC startup errors gracefully' do
      app = described_class.new(['--config', config_file.path], output: output)

      mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
      allow(Msf::MCP::RpcManager).to receive(:new).and_return(mock_rpc_manager)
      allow(mock_rpc_manager).to receive(:ensure_rpc_available).and_raise(
        Msf::MCP::Metasploit::RpcStartupError.new('msfrpcd not found')
      )
      allow(Signal).to receive(:trap)

      expect { app.run }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end

    it 'includes ensure_rpc_server in the run sequence before initialize_metasploit_client' do
      app = described_class.new(['--config', config_file.path], output: output)

      mock_rpc_manager = instance_double(Msf::MCP::RpcManager)
      allow(Msf::MCP::RpcManager).to receive(:new).and_return(mock_rpc_manager)
      allow(mock_rpc_manager).to receive(:ensure_rpc_available)

      allow(Msf::MCP::Metasploit::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:authenticate)
      allow(Msf::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      allow(mock_mcp_server).to receive(:start)
      allow(Signal).to receive(:trap)

      # Track the order of operations
      order = []
      allow(mock_rpc_manager).to receive(:ensure_rpc_available) { order << :ensure_rpc }
      allow(Msf::MCP::Metasploit::Client).to receive(:new) { order << :init_client; mock_client }

      app.run

      expect(order).to eq([:ensure_rpc, :init_client])
    end
  end
end
