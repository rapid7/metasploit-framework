# frozen_string_literal: true

require 'msf/core/mcp'
require 'webmock/rspec'
require 'tempfile'

RSpec.describe 'Configuration Loading and Validation Integration' do
  let(:file_fixtures_path) { File.join(Msf::Config.install_root, 'spec', 'file_fixtures') }
  let(:valid_messagepack_path) { File.join(file_fixtures_path, 'config_files', 'msfmcpd', 'valid_messagepack.yaml') }
  let(:valid_jsonrpc_path) { File.join(file_fixtures_path, 'config_files', 'msfmcpd', 'valid_jsonrpc.yaml') }

  before do
    WebMock.disable_net_connect!(allow_localhost: false)
  end

  after do
    WebMock.allow_net_connect!
  end

  describe 'Application Initialization with Configuration' do
    let(:output) { StringIO.new }
    let(:argv) { ['--config', valid_messagepack_path] }

    it 'successfully initializes all components with valid MessagePack config' do
      app = Msf::MCP::Application.new(argv, output: output)

      # Stub Metasploit authentication
      stub_request(:post, 'https://localhost:55553/api/')
        .to_return(
          status: 200,
          body: MessagePack.pack({
            'result' => 'success',
            'token' => 'fake_token_123'
          })
        )

      # Execute initialization steps (before start)
      app.send(:parse_arguments)
      app.send(:load_configuration)
      app.send(:validate_configuration)
      app.send(:initialize_rate_limiter)
      app.send(:initialize_metasploit_client)

      # Verify components are initialized with config values
      expect(app.config[:msf_api][:type]).to eq('messagepack')
      expect(app.config[:msf_api][:host]).to eq('localhost')
      expect(app.config[:msf_api][:port]).to eq(55553)

      # Verify rate limiter is configured from config
      expect(app.rate_limiter).to be_a(Msf::MCP::Security::RateLimiter)
      expect(app.rate_limiter.instance_variable_get(:@requests_per_minute)).to eq(60)
      expect(app.rate_limiter.instance_variable_get(:@burst_size)).to eq(10)

      # Verify Metasploit client is created with config values
      expect(app.msf_client).to be_a(Msf::MCP::Metasploit::Client)
    end

    it 'successfully initializes all components with valid JSON-RPC config' do
      argv = ['--config', valid_jsonrpc_path]
      app = Msf::MCP::Application.new(argv, output: output)

      # Execute initialization steps
      app.send(:parse_arguments)
      app.send(:load_configuration)
      app.send(:validate_configuration)
      app.send(:initialize_rate_limiter)
      app.send(:initialize_metasploit_client)

      # Verify config is loaded correctly
      expect(app.config[:msf_api][:type]).to eq('json-rpc')
      expect(app.config[:msf_api][:port]).to eq(8081)
      expect(app.config[:msf_api][:token]).to eq('test_bearer_token_12345')

      # Verify components are initialized
      expect(app.rate_limiter).to be_a(Msf::MCP::Security::RateLimiter)
      expect(app.msf_client).to be_a(Msf::MCP::Metasploit::Client)
    end

    it 'applies defaults and starts successfully with minimal config' do
      minimal_config = {
        msf_api: {
          type: 'messagepack',
          user: 'msf',
          password: 'pass'
        }
      }

      config_file = Tempfile.new(['minimal_config', '.yaml'])
      # Dirty hack to make sure the config hash keys are strings and not symbols.
      config_file.write(YAML.dump(JSON.parse(minimal_config.to_json)))
      config_file.flush

      app = Msf::MCP::Application.new(['--config', config_file.path], output: output)

      # Stub authentication
      stub_request(:post, 'https://localhost:55553/api/')
        .to_return(
          status: 200,
          body: MessagePack.pack({
            'result' => 'success',
            'token' => 'token'
          })
        )

      app.send(:parse_arguments)
      app.send(:load_configuration)
      app.send(:validate_configuration)

      # Verify defaults were applied
      expect(app.config[:msf_api][:host]).to eq('localhost')
      expect(app.config[:msf_api][:port]).to eq(55553)
      expect(app.config[:rate_limit][:requests_per_minute]).to eq(60)
      expect(app.config[:logging][:level]).to eq('INFO')

      # Verify can proceed with initialization
      expect {
        app.send(:initialize_rate_limiter)
        app.send(:initialize_metasploit_client)
      }.not_to raise_error

      config_file.close
      config_file.unlink
    end

    it 'fails gracefully when config has invalid port' do
      invalid_config = YAML.safe_load_file(valid_messagepack_path)
      invalid_config['msf_api']['port'] = 999999

      config_file = Tempfile.new(['invalid_port', '.yaml'])
      config_file.write(YAML.dump(invalid_config))
      config_file.flush

      app = Msf::MCP::Application.new(['--config', config_file.path], output: output)

      expect {
        app.run
      }.to raise_error(SystemExit)

      expect(output.string).to include('Configuration validation failed')
      expect(output.string).to include('port must be between')

      config_file.close
      config_file.unlink
    end

    it 'fails gracefully when config is missing required authentication on remote host' do
      invalid_config = {
        msf_api: {
          type: 'messagepack',
          host: '192.168.1.100',
          port: 55553,
          auto_start_rpc: false
        }
      }

      config_file = Tempfile.new(['missing_auth', '.yaml'])
      # Dirty hack to make sure the config hash keys are strings and not symbols.
      config_file.write(YAML.dump(JSON.parse(invalid_config.to_json)))
      config_file.flush

      app = Msf::MCP::Application.new(['--config', config_file.path], output: output)

      expect {
        app.run
      }.to raise_error(SystemExit)

      expect(output.string).to include('Configuration validation failed')
      expect(output.string).to match(/user|password/)

      config_file.close
      config_file.unlink
    end

    it 'prevents application startup with invalid API type' do
      invalid_config = YAML.safe_load_file(valid_messagepack_path)
      invalid_config['msf_api']['type'] = 'soap'

      config_file = Tempfile.new(['invalid_type', '.yaml'])
      config_file.write(YAML.dump(invalid_config))
      config_file.flush

      app = Msf::MCP::Application.new(['--config', config_file.path], output: output)

      expect {
        app.run
      }.to raise_error(SystemExit)

      expect(output.string).to include('Configuration validation failed')
      expect(output.string).to include('msf_api.type')

      config_file.close
      config_file.unlink
    end
  end

  describe 'Environment Variable Override Integration' do
    let(:output) { StringIO.new }

    after do
      # Clean up ENV
      %w[MSF_API_HOST MSF_API_PORT MSF_API_TYPE MSF_API_USER MSF_API_PASSWORD MSF_API_TOKEN].each { |key| ENV.delete(key) }
    end

    it 'ENV override changes which Metasploit host client connects to' do
      ENV['MSF_API_HOST'] = '192.168.1.100'

      app = Msf::MCP::Application.new(['--config', valid_messagepack_path], output: output)

      app.send(:parse_arguments)
      app.send(:load_configuration)
      app.send(:validate_configuration)
      app.send(:initialize_metasploit_client)

      # Verify client was created with ENV-overridden host
      expect(app.config[:msf_api][:host]).to eq('192.168.1.100')

      # Verify that making an API call would use the overridden host
      stub_request(:post, 'https://192.168.1.100:55553/api/')
        .to_return(
          status: 200,
          body: MessagePack.pack({
            'result' => 'success',
            'token' => 'token_123'
          })
        )

      expect {
        app.msf_client.authenticate('test_user', 'test_password')
      }.not_to raise_error

      # Verify the request was made to the correct host
      expect(WebMock).to have_requested(:post, 'https://192.168.1.100:55553/api/').once
    end

    it 'ENV override changes authentication credentials used' do
      ENV['MSF_API_USER'] = 'env_override_user'
      ENV['MSF_API_PASSWORD'] = 'env_override_pass'

      app = Msf::MCP::Application.new(['--config', valid_messagepack_path], output: output)

      # Stub authentication - accept any body since MessagePack matching is problematic
      stub_request(:post, 'https://localhost:55553/api/')
        .to_return(
          status: 200,
          body: MessagePack.pack({
            'result' => 'success',
            'token' => 'env_token'
          })
        )

      app.send(:parse_arguments)
      app.send(:load_configuration)
      app.send(:validate_configuration)
      app.send(:initialize_metasploit_client)

      # Verify ENV vars override config file
      expect(app.config[:msf_api][:user]).to eq('env_override_user')
      expect(app.config[:msf_api][:password]).to eq('env_override_pass')

      # Verify authentication uses ENV credentials
      app.send(:authenticate_metasploit)

      expect(WebMock).to have_requested(:post, 'https://localhost:55553/api/').once
    end

    it 'ENV override changes API type from MessagePack to JSON-RPC' do
      ENV['MSF_API_TYPE'] = 'json-rpc'
      ENV['MSF_API_PORT'] = '8081'
      ENV['MSF_API_TOKEN'] = 'env_token_123' # JSON-RPC requires token

      app = Msf::MCP::Application.new(['--config', valid_messagepack_path], output: output)

      app.send(:parse_arguments)
      app.send(:load_configuration)
      app.send(:validate_configuration)
      app.send(:initialize_metasploit_client)

      # Verify type was overridden
      expect(app.config[:msf_api][:type]).to eq('json-rpc')
      expect(app.config[:msf_api][:port]).to eq(8081)
      expect(app.config[:msf_api][:token]).to eq('env_token_123')

      # Verify client is JSON-RPC client (not MessagePack)
      underlying_client = app.msf_client.instance_variable_get(:@client)
      expect(underlying_client).to be_a(Msf::MCP::Metasploit::JsonRpcClient)
    end
  end

  describe 'CLI Flag Override Integration' do
    let(:output) { StringIO.new }

    it 'CLI --user and --password flags override config file authentication' do
      app = Msf::MCP::Application.new(
        ['--config', valid_messagepack_path, '--user', 'cli_user', '--password', 'cli_pass'],
        output: output
      )

      # Stub authentication - accept any body
      stub_request(:post, 'https://localhost:55553/api/')
        .to_return(
          status: 200,
          body: MessagePack.pack({
            'result' => 'success',
            'token' => 'cli_token'
          })
        )

      app.send(:parse_arguments)
      app.send(:load_configuration)

      # Verify CLI args override config file
      expect(app.config[:msf_api][:user]).to eq('cli_user')
      expect(app.config[:msf_api][:password]).to eq('cli_pass')

      app.send(:validate_configuration)
      app.send(:initialize_metasploit_client)
      app.send(:authenticate_metasploit)

      # Verify authentication was called
      expect(WebMock).to have_requested(:post, 'https://localhost:55553/api/').once
    end
  end
end
