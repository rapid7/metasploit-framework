# frozen_string_literal: true

require 'msf/core/mcp'
require 'tempfile'

RSpec.describe Msf::MCP::Config::Loader do
  let(:file_fixtures_path) { File.join(Msf::Config.install_root, 'spec', 'file_fixtures') }

  describe '.load' do
    context 'with valid YAML file' do
      let(:config_file) { File.join(file_fixtures_path, 'config_files', 'msfmcpd', 'valid_messagepack.yaml') }

      it 'loads configuration from file' do
        config = described_class.load(config_file)

        expect(config).to be_a(Hash)
        expect(config[:msf_api][:type]).to eq('messagepack')
        expect(config[:msf_api][:host]).to eq('localhost')
      end

      it 'returns configuration with symbolized keys' do
        config = described_class.load(config_file)

        expect(config.keys).to all(be_a(Symbol))
      end
    end

    context 'with file not found' do
      it 'raises ConfigurationError with descriptive message' do
        expect {
          described_class.load('/nonexistent/config.yaml')
        }.to raise_error(Msf::MCP::Config::ConfigurationError, /not found/)
      end
    end

    context 'with invalid YAML syntax' do
      let(:invalid_yaml_file) { Tempfile.new(['invalid', '.yaml']) }

      before do
        invalid_yaml_file.write("invalid: yaml: content:\n  - unbalanced")
        invalid_yaml_file.flush
      end

      after do
        invalid_yaml_file.close
        invalid_yaml_file.unlink
      end

      it 'raises ConfigurationError with YAML error details' do
        expect {
          described_class.load(invalid_yaml_file.path)
        }.to raise_error(Msf::MCP::Config::ConfigurationError, /Invalid YAML syntax/)
      end
    end

    context 'with non-hash YAML content' do
      let(:array_yaml_file) { Tempfile.new(['array', '.yaml']) }

      before do
        array_yaml_file.write("- item1\n- item2\n- item3")
        array_yaml_file.flush
      end

      after do
        array_yaml_file.close
        array_yaml_file.unlink
      end

      it 'raises ConfigurationError requiring hash/dictionary' do
        expect {
          described_class.load(array_yaml_file.path)
        }.to raise_error(Msf::MCP::Config::ConfigurationError, /must contain a YAML hash/)
      end
    end
  end

  describe '.load_from_hash' do
    context 'with minimal configuration' do
      let(:config_hash) do
        {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'pass'
          }
        }
      end

      it 'applies default values' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:msf_api][:port]).to eq(55553)
        expect(config[:msf_api][:endpoint]).to eq('/api/')
        expect(config[:mcp][:transport]).to eq('stdio')
      end

      it 'applies rate limit defaults' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:rate_limit][:enabled]).to be true
        expect(config[:rate_limit][:requests_per_minute]).to eq(60)
        expect(config[:rate_limit][:burst_size]).to eq(10)
      end

      it 'applies logging defaults' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:logging][:enabled]).to be false
        expect(config[:logging][:level]).to eq('INFO')
      end
    end

    context 'with JSON-RPC configuration' do
      let(:config_hash) do
        {
          msf_api: {
            type: 'json-rpc',
            host: 'localhost',
            token: 'token123'
          }
        }
      end

      it 'applies JSON-RPC default port' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:msf_api][:port]).to eq(8081)
      end

      it 'applies JSON-RPC default endpoint' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:msf_api][:endpoint]).to eq('/api/v1/json-rpc')
      end
    end

    context 'with partial defaults override' do
      let(:config_hash) do
        {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            port: 9999,
            user: 'msf',
            password: 'pass'
          },
          rate_limit: { requests_per_minute: 120 }
        }
      end

      it 'preserves explicit port setting' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:msf_api][:port]).to eq(9999)
      end

      it 'merges rate limit defaults with provided values' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:rate_limit][:requests_per_minute]).to eq(120)
        expect(config[:rate_limit][:enabled]).to be true
        expect(config[:rate_limit][:burst_size]).to eq(10)
      end
    end

    context 'with disabled rate limiting' do
      let(:config_hash) do
        {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'pass'
          },
          rate_limit: { enabled: false }
        }
      end

      it 'respects disabled rate limiting' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:rate_limit][:enabled]).to be false
      end
    end
  end

  describe 'default values' do
    context 'with completely empty configuration' do
      let(:config_hash) { {} }

      it 'creates all nested configuration hashes' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:msf_api]).to be_a(Hash)
        expect(config[:mcp]).to be_a(Hash)
        expect(config[:rate_limit]).to be_a(Hash)
        expect(config[:logging]).to be_a(Hash)
      end
    end

    context 'MSF API defaults' do
      let(:config_hash) { {} }

      it 'sets default type to messagepack' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:msf_api][:type]).to eq('messagepack')
      end

      it 'sets default host to localhost' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:msf_api][:host]).to eq('localhost')
      end

      it 'sets default port to 55553 for messagepack' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:msf_api][:port]).to eq(55553)
      end

      it 'sets default ssl to true' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:msf_api][:ssl]).to be true
      end

      it 'sets default endpoint to /api/ for messagepack' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:msf_api][:endpoint]).to eq('/api/')
      end

      it 'sets default auto_start_rpc to true' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:msf_api][:auto_start_rpc]).to be true
      end

      context 'when type is json-rpc' do
        let(:config_hash) { { msf_api: { type: 'json-rpc' } } }

        it 'sets default port to 8081' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:msf_api][:port]).to eq(8081)
        end

        it 'sets default endpoint to /api/v1/json-rpc' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:msf_api][:endpoint]).to eq('/api/v1/json-rpc')
        end
      end

      context 'when ssl is explicitly set to false' do
        let(:config_hash) { { msf_api: { ssl: false } } }

        it 'preserves explicit false value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:msf_api][:ssl]).to be false
        end
      end

      context 'when ssl is explicitly set to true' do
        let(:config_hash) { { msf_api: { ssl: true } } }

        it 'preserves explicit true value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:msf_api][:ssl]).to be true
        end
      end

      context 'when auto_start_rpc is explicitly set to false' do
        let(:config_hash) { { msf_api: { auto_start_rpc: false } } }

        it 'preserves explicit false value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:msf_api][:auto_start_rpc]).to be false
        end
      end

      context 'when auto_start_rpc is explicitly set to true' do
        let(:config_hash) { { msf_api: { auto_start_rpc: true } } }

        it 'preserves explicit true value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:msf_api][:auto_start_rpc]).to be true
        end
      end
    end

    context 'MCP defaults' do
      let(:config_hash) { {} }

      it 'sets default transport to stdio' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:mcp][:transport]).to eq('stdio')
      end

      context 'with stdio transport' do
        let(:config_hash) { { mcp: { transport: 'stdio' } } }

        it 'does not set host for stdio transport' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:mcp][:host]).to be_nil
        end

        it 'does not set port for stdio transport' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:mcp][:port]).to be_nil
        end
      end

      context 'with http transport' do
        let(:config_hash) { { mcp: { transport: 'http' } } }

        it 'sets default host to localhost' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:mcp][:host]).to eq('localhost')
        end

        it 'sets default port to 3000' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:mcp][:port]).to eq(3000)
        end
      end

      context 'with http transport and explicit values' do
        let(:config_hash) do
          {
            mcp: {
              transport: 'http',
              host: '0.0.0.0',
              port: 8080
            }
          }
        end

        it 'preserves explicit host value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:mcp][:host]).to eq('0.0.0.0')
        end

        it 'preserves explicit port value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:mcp][:port]).to eq(8080)
        end
      end
    end

    context 'rate limit defaults' do
      let(:config_hash) { {} }

      it 'sets default enabled to true' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:rate_limit][:enabled]).to be true
      end

      it 'sets default requests_per_minute to 60' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:rate_limit][:requests_per_minute]).to eq(60)
      end

      it 'sets default burst_size to 10' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:rate_limit][:burst_size]).to eq(10)
      end

      context 'when rate_limit is explicitly disabled' do
        let(:config_hash) { { rate_limit: { enabled: false } } }

        it 'preserves explicit false value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:rate_limit][:enabled]).to be false
        end

        it 'still applies other defaults' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:rate_limit][:requests_per_minute]).to eq(60)
          expect(config[:rate_limit][:burst_size]).to eq(10)
        end
      end

      context 'with partial rate_limit configuration' do
        let(:config_hash) { { rate_limit: { requests_per_minute: 100 } } }

        it 'applies defaults for missing values' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:rate_limit][:enabled]).to be true
          expect(config[:rate_limit][:burst_size]).to eq(10)
        end

        it 'preserves explicit values' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:rate_limit][:requests_per_minute]).to eq(100)
        end
      end
    end

    context 'logging defaults' do
      let(:config_hash) { {} }
      let(:default_log_file) { File.join(Msf::Config.log_directory, 'msfmcp.log') }

      it 'sets default enabled to false' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:logging][:enabled]).to be false
      end

      it 'sets default level to INFO' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:logging][:level]).to eq('INFO')
      end

      it 'sets default log_file to msfmcp.log in the default Msf log directory' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:logging][:log_file]).to eq(default_log_file)
      end

      it 'sets default sanitize to true' do
        config = described_class.load_from_hash(config_hash)
        expect(config[:logging][:sanitize]).to be true
      end

      context 'when logging is explicitly enabled' do
        let(:config_hash) { { logging: { enabled: true } } }

        it 'preserves explicit true value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:logging][:enabled]).to be true
        end

        it 'still applies other defaults' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:logging][:level]).to eq('INFO')
          expect(config[:logging][:log_file]).to eq(default_log_file)
          expect(config[:logging][:sanitize]).to be true
        end
      end

      context 'when sanitize is explicitly set to false' do
        let(:config_hash) { { logging: { sanitize: false } } }

        it 'preserves explicit false value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:logging][:sanitize]).to be false
        end
      end

      context 'when sanitize is explicitly set to true' do
        let(:config_hash) { { logging: { sanitize: true } } }

        it 'preserves explicit true value' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:logging][:sanitize]).to be true
        end
      end

      context 'with partial logging configuration' do
        let(:config_hash) { { logging: { level: 'DEBUG', log_file: 'custom.log' } } }

        it 'applies default for enabled' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:logging][:enabled]).to be false
        end

        it 'applies default for sanitize' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:logging][:sanitize]).to be true
        end

        it 'preserves explicit values' do
          config = described_class.load_from_hash(config_hash)
          expect(config[:logging][:level]).to eq('DEBUG')
          expect(config[:logging][:log_file]).to eq('custom.log')
        end
      end
    end

    context 'preserving existing values' do
      let(:config_hash) do
        {
          msf_api: {
            type: 'json-rpc',
            host: 'remote.example.com',
            port: 9000,
            ssl: false,
            endpoint: '/custom/api/',
            token: 'custom_token'
          },
          mcp: {
            transport: 'http',
            host: '192.168.1.100',
            port: 5000
          },
          rate_limit: {
            enabled: false,
            requests_per_minute: 120,
            burst_size: 20
          },
          logging: {
            enabled: true,
            level: 'DEBUG',
            log_file: 'debug.log'
          }
        }
      end

      it 'does not override any explicitly set values' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:msf_api][:type]).to eq('json-rpc')
        expect(config[:msf_api][:host]).to eq('remote.example.com')
        expect(config[:msf_api][:port]).to eq(9000)
        expect(config[:msf_api][:ssl]).to be false
        expect(config[:msf_api][:endpoint]).to eq('/custom/api/')
        expect(config[:msf_api][:token]).to eq('custom_token')

        expect(config[:mcp][:transport]).to eq('http')
        expect(config[:mcp][:host]).to eq('192.168.1.100')
        expect(config[:mcp][:port]).to eq(5000)

        expect(config[:rate_limit][:enabled]).to be false
        expect(config[:rate_limit][:requests_per_minute]).to eq(120)
        expect(config[:rate_limit][:burst_size]).to eq(20)

        expect(config[:logging][:enabled]).to be true
        expect(config[:logging][:level]).to eq('DEBUG')
        expect(config[:logging][:log_file]).to eq('debug.log')
      end
    end
  end

  describe 'environment variable overrides' do
    let(:config_file) { File.join(file_fixtures_path, 'config_files', 'msfmcpd', 'valid_messagepack.yaml') }
    let(:env_vars) do
      %w[
        MSF_API_TYPE MSF_API_HOST MSF_API_PORT MSF_API_SSL MSF_API_ENDPOINT
        MSF_API_USER MSF_API_PASSWORD MSF_API_TOKEN MSF_AUTO_START_RPC
        MSF_MCP_TRANSPORT MSF_MCP_HOST MSF_MCP_PORT
      ]
    end

    before do
      env_vars.each { |var| ENV.delete(var) }
    end

    after do
      env_vars.each { |var| ENV.delete(var) }
    end

    context 'MSF API configuration overrides' do
      context 'when MSF_API_TYPE is set' do
        before { ENV['MSF_API_TYPE'] = 'json-rpc' }

        it 'overrides the type value' do
          config = described_class.load(config_file)
          expect(config[:msf_api][:type]).to eq('json-rpc')
        end
      end

      context 'when MSF_API_HOST is set' do
        before { ENV['MSF_API_HOST'] = 'override.example.com' }

        it 'overrides the host value' do
          config = described_class.load(config_file)
          expect(config[:msf_api][:host]).to eq('override.example.com')
        end
      end

      context 'when MSF_API_PORT is set' do
        before { ENV['MSF_API_PORT'] = '9999' }

        it 'overrides the port value as integer' do
          config = described_class.load(config_file)
          expect(config[:msf_api][:port]).to eq(9999)
        end
      end

      context 'when MSF_API_SSL is set' do
        let(:ssl_false_config) do
          { msf_api: { type: 'messagepack', host: 'localhost', ssl: false } }
        end

        context "to '0'" do
          before { ENV['MSF_API_SSL'] = '0' }

          it 'overrides SSL to false' do
            config = described_class.load(config_file)
            expect(config[:msf_api][:ssl]).to be false
          end
        end

        context "to 'false'" do
          before { ENV['MSF_API_SSL'] = 'false' }

          it 'overrides SSL to false' do
            config = described_class.load(config_file)
            expect(config[:msf_api][:ssl]).to be false
          end
        end

        context "to '1'" do
          before { ENV['MSF_API_SSL'] = '1' }

          it 'overrides SSL to true' do
            config = described_class.load_from_hash(ssl_false_config)
            expect(config[:msf_api][:ssl]).to be true
          end
        end

        context "to 'true'" do
          before { ENV['MSF_API_SSL'] = 'true' }

          it 'overrides SSL to true' do
            config = described_class.load_from_hash(ssl_false_config)
            expect(config[:msf_api][:ssl]).to be true
          end
        end

        context "to 'yes'" do
          before { ENV['MSF_API_SSL'] = 'yes' }

          it 'overrides SSL to true' do
            config = described_class.load_from_hash(ssl_false_config)
            expect(config[:msf_api][:ssl]).to be true
          end
        end

        context "to empty string" do
          before { ENV['MSF_API_SSL'] = '' }

          it 'does not override SSL' do
            config = described_class.load(config_file)
            expect(config[:msf_api][:ssl]).to be true
          end
        end
      end

      context 'when MSF_API_ENDPOINT is set' do
        before { ENV['MSF_API_ENDPOINT'] = '/custom/api/v2/' }

        it 'overrides the endpoint value' do
          config = described_class.load(config_file)
          expect(config[:msf_api][:endpoint]).to eq('/custom/api/v2/')
        end
      end

      context 'when MSF_API_USER is set' do
        before { ENV['MSF_API_USER'] = 'env_user' }

        it 'overrides the user value' do
          config = described_class.load(config_file)
          expect(config[:msf_api][:user]).to eq('env_user')
        end
      end

      context 'when MSF_API_PASSWORD is set' do
        before { ENV['MSF_API_PASSWORD'] = 'env_password' }

        it 'overrides the password value' do
          config = described_class.load(config_file)
          expect(config[:msf_api][:password]).to eq('env_password')
        end
      end

      context 'when MSF_API_TOKEN is set' do
        before { ENV['MSF_API_TOKEN'] = 'env_token_123' }

        it 'overrides the token value' do
          config = described_class.load(config_file)
          expect(config[:msf_api][:token]).to eq('env_token_123')
        end
      end

      context 'when MSF_AUTO_START_RPC is set' do
        context "to 'false'" do
          before { ENV['MSF_AUTO_START_RPC'] = 'false' }

          it 'overrides auto_start_rpc to false' do
            config = described_class.load(config_file)
            expect(config[:msf_api][:auto_start_rpc]).to be false
          end
        end

        context "to '0'" do
          before { ENV['MSF_AUTO_START_RPC'] = '0' }

          it 'overrides auto_start_rpc to false' do
            config = described_class.load(config_file)
            expect(config[:msf_api][:auto_start_rpc]).to be false
          end
        end

        context "to 'true'" do
          before { ENV['MSF_AUTO_START_RPC'] = 'true' }

          it 'overrides auto_start_rpc to true' do
            config = described_class.load_from_hash({ msf_api: { auto_start_rpc: false } })
            expect(config[:msf_api][:auto_start_rpc]).to be true
          end
        end

        context "to '1'" do
          before { ENV['MSF_AUTO_START_RPC'] = '1' }

          it 'overrides auto_start_rpc to true' do
            config = described_class.load_from_hash({ msf_api: { auto_start_rpc: false } })
            expect(config[:msf_api][:auto_start_rpc]).to be true
          end
        end

        context "to 'yes'" do
          before { ENV['MSF_AUTO_START_RPC'] = 'yes' }

          it 'overrides auto_start_rpc to true' do
            config = described_class.load_from_hash({ msf_api: { auto_start_rpc: false } })
            expect(config[:msf_api][:auto_start_rpc]).to be true
          end
        end
      end
    end

    context 'MCP configuration overrides' do
      context 'when MSF_MCP_TRANSPORT is set' do
        before { ENV['MSF_MCP_TRANSPORT'] = 'http' }

        it 'overrides the transport value' do
          config = described_class.load(config_file)
          expect(config[:mcp][:transport]).to eq('http')
        end
      end

      context 'when MSF_MCP_HOST is set' do
        before { ENV['MSF_MCP_HOST'] = '0.0.0.0' }

        it 'overrides the MCP host value' do
          config = described_class.load(config_file)
          expect(config[:mcp][:host]).to eq('0.0.0.0')
        end
      end

      context 'when MSF_MCP_PORT is set' do
        before { ENV['MSF_MCP_PORT'] = '8080' }

        it 'overrides the MCP port value as integer' do
          config = described_class.load(config_file)
          expect(config[:mcp][:port]).to eq(8080)
        end
      end
    end

    context 'with multiple ENV vars set' do
      before do
        ENV['MSF_API_TYPE'] = 'json-rpc'
        ENV['MSF_API_HOST'] = 'multi.example.com'
        ENV['MSF_API_PORT'] = '7777'
        ENV['MSF_API_USER'] = 'multi_user'
        ENV['MSF_API_PASSWORD'] = 'multi_pass'
        ENV['MSF_API_TOKEN'] = 'multi_token'
        ENV['MSF_MCP_TRANSPORT'] = 'http'
        ENV['MSF_MCP_HOST'] = '127.0.0.1'
        ENV['MSF_MCP_PORT'] = '3000'
      end

      it 'overrides all specified values simultaneously' do
        config = described_class.load(config_file)

        expect(config[:msf_api][:type]).to eq('json-rpc')
        expect(config[:msf_api][:host]).to eq('multi.example.com')
        expect(config[:msf_api][:port]).to eq(7777)
        expect(config[:msf_api][:user]).to eq('multi_user')
        expect(config[:msf_api][:password]).to eq('multi_pass')
        expect(config[:msf_api][:token]).to eq('multi_token')
        expect(config[:mcp][:transport]).to eq('http')
        expect(config[:mcp][:host]).to eq('127.0.0.1')
        expect(config[:mcp][:port]).to eq(3000)
      end
    end

    context 'with partial ENV overrides' do
      before do
        ENV['MSF_API_HOST'] = 'partial.example.com'
        ENV['MSF_MCP_TRANSPORT'] = 'http'
      end

      it 'overrides only specified values while keeping others' do
        config = described_class.load(config_file)

        expect(config[:msf_api][:host]).to eq('partial.example.com')
        expect(config[:mcp][:transport]).to eq('http')
        # Other values should remain from file or defaults
        expect(config[:msf_api][:port]).to be_a(Integer)
        expect(config[:msf_api][:endpoint]).to eq('/api/')
      end
    end

    context 'when ENV vars are empty strings' do
      before do
        ENV['MSF_API_HOST'] = ''
        ENV['MSF_API_PORT'] = ''
      end

      it 'overrides with empty strings (current behavior)' do
        config = described_class.load(config_file)

        # Current implementation: empty strings DO override values
        # This tests the actual behavior, though it might not be ideal
        expect(config[:msf_api][:host]).to eq('')
        expect(config[:msf_api][:port]).to eq(0) # Empty string converts to 0
      end
    end

    context 'using load_from_hash with ENV overrides' do
      let(:config_hash) do
        {
          msf_api: {
            type: 'messagepack',
            host: 'hash.example.com',
            port: 5555,
            user: 'hash_user',
            password: 'hash_pass'
          },
          mcp: {
            transport: 'stdio'
          }
        }
      end

      before do
        ENV['MSF_API_TYPE'] = 'json-rpc'
        ENV['MSF_API_HOST'] = 'env.example.com'
        ENV['MSF_API_PORT'] = '6666'
        ENV['MSF_MCP_TRANSPORT'] = 'http'
      end

      it 'applies ENV overrides on top of hash configuration' do
        config = described_class.load_from_hash(config_hash)

        expect(config[:msf_api][:type]).to eq('json-rpc')
        expect(config[:msf_api][:host]).to eq('env.example.com')
        expect(config[:msf_api][:port]).to eq(6666)
        expect(config[:msf_api][:user]).to eq('hash_user') # Not overridden
        expect(config[:mcp][:transport]).to eq('http')
      end
    end
  end
end
