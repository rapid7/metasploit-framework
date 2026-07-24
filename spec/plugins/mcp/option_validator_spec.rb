# frozen_string_literal: true

require 'spec_helper'
require 'rex/text'
require Metasploit::Framework.root.join('plugins/mcp.rb').to_path

RSpec.describe Msf::Plugin::MCP do
  include_context 'Msf::UIDriver'

  let(:framework) { instance_double(Msf::Framework) }
  let(:output) { driver_output }
  let(:base_opts) { { 'LocalOutput' => output } }

  let(:plugins_collection) do
    instance_double('Msf::PluginManager').tap do |pm|
      allow(pm).to receive(:find).and_return(nil)
      allow(pm).to receive(:load).and_return(true)
    end
  end

  let(:threads_manager) do
    instance_double('Msf::Framework::ThreadManager').tap do |tm|
      allow(tm).to receive(:spawn).and_return(Thread.new {})
    end
  end

  let(:mock_client) do
    instance_double('Msf::MCP::Metasploit::Client').tap do |c|
      allow(c).to receive(:authenticate).and_return('token')
      allow(c).to receive(:shutdown)
    end
  end

  before do
    allow(framework).to receive(:plugins).and_return(plugins_collection)
    allow(framework).to receive(:threads).and_return(threads_manager)
    stub_const('Msf::MCP::Metasploit::Client', Class.new do
      def initialize(**_args); end
      def authenticate(*_args); 'token'; end
      def shutdown; end
    end)
    stub_const('Msf::MCP::Security::RateLimiter', Class.new do
      def initialize(**_args); end
    end)
    stub_const('Msf::MCP::Server', Class.new do
      def initialize(**_args); end
      def start(**_args); end
      def shutdown; end
    end)
    allow(Rex::Text).to receive(:rand_text_alphanumeric).with(12).and_return('abcdefghijkl')

    mock_dispatcher = instance_double(described_class::McpCommandDispatcher)
    allow(mock_dispatcher).to receive(:plugin=)
    allow_any_instance_of(described_class).to receive(:add_console_dispatcher).and_return(mock_dispatcher)
    allow_any_instance_of(described_class).to receive(:remove_console_dispatcher)
  end

  subject(:plugin) { described_class.new(framework, base_opts) }

  describe '#validate_options!' do
    describe 'ServerPort' do
      it 'accepts port 1' do
        expect { plugin.send(:validate_options!, { 'ServerPort' => '1' }) }.not_to raise_error
      end

      it 'accepts port 3000' do
        expect { plugin.send(:validate_options!, { 'ServerPort' => '3000' }) }.not_to raise_error
      end

      it 'accepts port 65535' do
        expect { plugin.send(:validate_options!, { 'ServerPort' => '65535' }) }.not_to raise_error
      end

      it 'rejects port 0' do
        expect { plugin.send(:validate_options!, { 'ServerPort' => '0' }) }.to raise_error(Msf::MCP::Config::ValidationError, /ServerPort/)
      end

      it 'rejects port 65536' do
        expect { plugin.send(:validate_options!, { 'ServerPort' => '65536' }) }.to raise_error(Msf::MCP::Config::ValidationError, /ServerPort/)
      end

      it 'rejects non-numeric value "abc"' do
        expect { plugin.send(:validate_options!, { 'ServerPort' => 'abc' }) }.to raise_error(Msf::MCP::Config::ValidationError, /ServerPort/)
      end

      it 'is optional (nil is accepted)' do
        expect { plugin.send(:validate_options!, {}) }.not_to raise_error
      end
    end

    describe 'RpcPort' do
      it 'accepts port 1' do
        expect { plugin.send(:validate_options!, { 'RpcPort' => '1' }) }.not_to raise_error
      end

      it 'accepts port 55552' do
        expect { plugin.send(:validate_options!, { 'RpcPort' => '55552' }) }.not_to raise_error
      end

      it 'accepts port 65535' do
        expect { plugin.send(:validate_options!, { 'RpcPort' => '65535' }) }.not_to raise_error
      end

      it 'rejects port 0' do
        expect { plugin.send(:validate_options!, { 'RpcPort' => '0' }) }.to raise_error(Msf::MCP::Config::ValidationError, /RpcPort/)
      end

      it 'rejects port 65536' do
        expect { plugin.send(:validate_options!, { 'RpcPort' => '65536' }) }.to raise_error(Msf::MCP::Config::ValidationError, /RpcPort/)
      end

      it 'rejects non-numeric value "abc"' do
        expect { plugin.send(:validate_options!, { 'RpcPort' => 'abc' }) }.to raise_error(Msf::MCP::Config::ValidationError, /RpcPort/)
      end
    end

    describe 'RpcSSL' do
      it 'accepts "true"' do
        expect { plugin.send(:validate_options!, { 'RpcSSL' => 'true' }) }.not_to raise_error
      end

      it 'accepts "false"' do
        expect { plugin.send(:validate_options!, { 'RpcSSL' => 'false' }) }.not_to raise_error
      end

      it 'accepts "TRUE" case-insensitively' do
        expect { plugin.send(:validate_options!, { 'RpcSSL' => 'TRUE' }) }.not_to raise_error
      end

      it 'accepts "False" case-insensitively' do
        expect { plugin.send(:validate_options!, { 'RpcSSL' => 'False' }) }.not_to raise_error
      end

      it 'rejects "yes"' do
        expect { plugin.send(:validate_options!, { 'RpcSSL' => 'yes' }) }.to raise_error(Msf::MCP::Config::ValidationError, /RpcSSL/)
      end

      it 'rejects "1"' do
        expect { plugin.send(:validate_options!, { 'RpcSSL' => '1' }) }.to raise_error(Msf::MCP::Config::ValidationError, /RpcSSL/)
      end

      it 'rejects empty string' do
        expect { plugin.send(:validate_options!, { 'RpcSSL' => '' }) }.to raise_error(Msf::MCP::Config::ValidationError, /RpcSSL/)
      end
    end

    describe 'DangerousActions' do
      it 'accepts "true"' do
        expect { plugin.send(:validate_options!, { 'DangerousActions' => 'true' }) }.not_to raise_error
      end

      it 'accepts "false"' do
        expect { plugin.send(:validate_options!, { 'DangerousActions' => 'false' }) }.not_to raise_error
      end

      it 'accepts "TRUE" case-insensitively' do
        expect { plugin.send(:validate_options!, { 'DangerousActions' => 'TRUE' }) }.not_to raise_error
      end

      it 'accepts "False" case-insensitively' do
        expect { plugin.send(:validate_options!, { 'DangerousActions' => 'False' }) }.not_to raise_error
      end

      it 'rejects "yes"' do
        expect { plugin.send(:validate_options!, { 'DangerousActions' => 'yes' }) }.to raise_error(Msf::MCP::Config::ValidationError, /DangerousActions/)
      end
    end

    describe 'RateLimit' do
      it 'accepts value 1' do
        expect { plugin.send(:validate_options!, { 'RateLimit' => '1' }) }.not_to raise_error
      end

      it 'accepts value 60' do
        expect { plugin.send(:validate_options!, { 'RateLimit' => '60' }) }.not_to raise_error
      end

      it 'accepts value 10000' do
        expect { plugin.send(:validate_options!, { 'RateLimit' => '10000' }) }.not_to raise_error
      end

      it 'rejects value 0' do
        expect { plugin.send(:validate_options!, { 'RateLimit' => '0' }) }.to raise_error(Msf::MCP::Config::ValidationError, /RateLimit/)
      end

      it 'rejects value 10001' do
        expect { plugin.send(:validate_options!, { 'RateLimit' => '10001' }) }.to raise_error(Msf::MCP::Config::ValidationError, /RateLimit/)
      end

      it 'rejects non-numeric value "fast"' do
        expect { plugin.send(:validate_options!, { 'RateLimit' => 'fast' }) }.to raise_error(Msf::MCP::Config::ValidationError, /RateLimit/)
      end
    end

    describe 'RPC credential pairing' do
      it 'raises an error when RpcUser is provided without RpcPass' do
        expect {
          plugin.send(:validate_options!, { 'RpcUser' => 'msf', 'RpcPass' => '' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /RpcPass/)
      end

      it 'raises an error when RpcUser is provided and RpcPass is nil' do
        expect {
          plugin.send(:validate_options!, { 'RpcUser' => 'msf' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /RpcPass/)
      end

      it 'raises an error when RpcPass is provided without RpcUser' do
        expect {
          plugin.send(:validate_options!, { 'RpcPass' => 'secret', 'RpcUser' => '' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /RpcUser/)
      end

      it 'raises an error when RpcPass is provided and RpcUser is nil' do
        expect {
          plugin.send(:validate_options!, { 'RpcPass' => 'secret' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /RpcUser/)
      end

      it 'accepts when both RpcUser and RpcPass are provided' do
        expect {
          plugin.send(:validate_options!, { 'RpcUser' => 'msf', 'RpcPass' => 'secret' })
        }.not_to raise_error
      end

      it 'accepts when neither RpcUser nor RpcPass is provided' do
        expect { plugin.send(:validate_options!, {}) }.not_to raise_error
      end
    end

    describe 'error messages' do
      it 'names the offending option in the error for ServerPort' do
        expect {
          plugin.send(:validate_options!, { 'ServerPort' => 'bad' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /Invalid value for ServerPort/)
      end

      it 'includes the expected format for ServerPort' do
        expect {
          plugin.send(:validate_options!, { 'ServerPort' => 'bad' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /integer between 1 and 65535/)
      end

      it 'names the offending option in the error for RpcSSL' do
        expect {
          plugin.send(:validate_options!, { 'RpcSSL' => 'maybe' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /Invalid value for RpcSSL/)
      end

      it 'includes the expected format for RpcSSL' do
        expect {
          plugin.send(:validate_options!, { 'RpcSSL' => 'maybe' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /\"true\" or \"false\"/)
      end

      it 'names the offending option in the error for RateLimit' do
        expect {
          plugin.send(:validate_options!, { 'RateLimit' => '-1' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /Invalid value for RateLimit/)
      end

      it 'includes the expected format for RateLimit' do
        expect {
          plugin.send(:validate_options!, { 'RateLimit' => '-1' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /integer between 1 and 10000/)
      end
    end
  end

  describe '#resolve_config' do
    describe 'provided options appear in the resolved config' do
      it 'maps ServerHost to mcp[:host]' do
        config = plugin.send(:resolve_config, { 'ServerHost' => '0.0.0.0' })
        expect(config[:mcp][:host]).to eq('0.0.0.0')
      end

      it 'maps ServerPort to mcp[:port]' do
        config = plugin.send(:resolve_config, { 'ServerPort' => '8080' })
        expect(config[:mcp][:port]).to eq(8080)
      end

      it 'maps RateLimit to rate_limit[:requests_per_minute]' do
        config = plugin.send(:resolve_config, { 'RateLimit' => '120' })
        expect(config[:rate_limit][:requests_per_minute]).to eq(120)
      end

      it 'sets rate_limit[:burst_size] equal to requests_per_minute' do
        config = plugin.send(:resolve_config, { 'RateLimit' => '120' })
        expect(config[:rate_limit][:burst_size]).to eq(120)
      end
    end

    describe 'default values when options are omitted' do
      let(:config) { plugin.send(:resolve_config, {}) }

      it 'defaults mcp[:transport] to "http"' do
        expect(config[:mcp][:transport]).to eq('http')
      end

      it 'defaults mcp[:host] to "localhost"' do
        expect(config[:mcp][:host]).to eq('localhost')
      end

      it 'defaults mcp[:port] to 3000' do
        expect(config[:mcp][:port]).to eq(3000)
      end

      it 'defaults rate_limit[:requests_per_minute] to 60' do
        expect(config[:rate_limit][:requests_per_minute]).to eq(60)
      end

      it 'defaults rate_limit[:burst_size] to 60' do
        expect(config[:rate_limit][:burst_size]).to eq(60)
      end
    end

  end
end
