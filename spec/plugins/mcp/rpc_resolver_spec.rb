# frozen_string_literal: true

require 'spec_helper'
require 'rex/text'
require Metasploit::Framework.root.join('plugins/mcp.rb').to_path

RSpec.describe Msf::Plugin::MCP do
  include_context 'Msf::UIDriver'

  let(:framework) { instance_double(Msf::Framework) }
  let(:output) { driver_output }
  let(:base_opts) { { 'LocalOutput' => output } }

  let(:threads_manager) do
    instance_double('Msf::Framework::ThreadManager').tap do |tm|
      allow(tm).to receive(:spawn).and_return(Thread.new {})
    end
  end

  before do
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

    mock_dispatcher = instance_double(described_class::McpCommandDispatcher)
    allow(mock_dispatcher).to receive(:plugin=)
    allow_any_instance_of(described_class).to receive(:add_console_dispatcher).and_return(mock_dispatcher)
    allow_any_instance_of(described_class).to receive(:remove_console_dispatcher)
  end

  subject(:plugin) { described_class.new(framework, base_opts) }

  describe '#resolve_rpc_config' do
    describe 'introspection of loaded msgrpc plugin' do
      let(:msgrpc_server) do
        instance_double(
          'Msf::RPC::Service',
          srvhost: '127.0.0.1',
          srvport: 55552,
          users: { 'msf' => 'introspected_pass' },
          options: { ssl: true }
        )
      end

      let(:msgrpc_plugin) do
        instance_double('Msf::Plugin::MSGRPC', name: 'msgrpc', server: msgrpc_server)
      end

      let(:plugins_collection) do
        [msgrpc_plugin]
      end

      before do
        allow(framework).to receive(:plugins).and_return(plugins_collection)
      end

      it 'extracts the host from the msgrpc server' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:host]).to eq('127.0.0.1')
      end

      it 'extracts the port from the msgrpc server' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:port]).to eq(55552)
      end

      it 'extracts the username from the msgrpc server users hash' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:user]).to eq('msf')
      end

      it 'extracts the password from the msgrpc server users hash' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:pass]).to eq('introspected_pass')
      end

      it 'extracts the ssl setting from the msgrpc server options' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:ssl]).to eq(true)
      end

      it 'does not set auto_started_rpc flag' do
        plugin.send(:resolve_rpc_config, {})
        expect(plugin.auto_started_rpc).to eq(false)
      end
    end

    describe 'auto-start path' do
      let(:plugins_collection) do
        instance_double('Msf::PluginManager').tap do |pm|
          allow(pm).to receive(:find).and_return(nil)
          allow(pm).to receive(:load).and_return(true)
        end
      end

      before do
        allow(framework).to receive(:plugins).and_return(plugins_collection)
        allow(Rex::Text).to receive(:rand_text_alphanumeric).with(12).and_return('abcdefghijkl')
      end

      it 'generates a password of at least 8 characters' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:pass].length).to be >= 8
      end

      it 'prints credentials to the console' do
        plugin.send(:resolve_rpc_config, {})
        expect(@output.join("\n")).to match(/msf/)
        expect(@output.join("\n")).to match(/abcdefghijkl/)
      end

      it 'sets auto_started_rpc flag to true' do
        plugin.send(:resolve_rpc_config, {})
        expect(plugin.auto_started_rpc).to eq(true)
      end

      it 'loads the msgrpc plugin via framework.plugins' do
        expect(plugins_collection).to receive(:load).with('msgrpc', hash_including('Pass' => 'abcdefghijkl'))
        plugin.send(:resolve_rpc_config, {})
      end

      it 'uses "msf" as the default username' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:user]).to eq('msf')
      end

      it 'defaults host to 127.0.0.1' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:host]).to eq('127.0.0.1')
      end

      it 'defaults port to 55552' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:port]).to eq(55_552)
      end
    end

    describe 'explicit credentials path overrides introspected values' do
      let(:msgrpc_server) do
        instance_double(
          'Msf::RPC::Service',
          srvhost: '10.0.0.1',
          srvport: 55553,
          users: { 'other_user' => 'other_pass' },
          options: { ssl: false }
        )
      end

      let(:msgrpc_plugin) do
        instance_double('Msf::Plugin::MSGRPC', name: 'msgrpc', server: msgrpc_server)
      end

      let(:plugins_collection) do
        [msgrpc_plugin]
      end

      before do
        allow(framework).to receive(:plugins).and_return(plugins_collection)
      end

      it 'uses explicit RpcUser instead of introspected user' do
        config = plugin.send(:resolve_rpc_config, { 'RpcUser' => 'admin', 'RpcPass' => 'explicit_pass' })
        expect(config[:user]).to eq('admin')
      end

      it 'uses explicit RpcPass instead of introspected password' do
        config = plugin.send(:resolve_rpc_config, { 'RpcUser' => 'admin', 'RpcPass' => 'explicit_pass' })
        expect(config[:pass]).to eq('explicit_pass')
      end

      it 'uses introspected host/port/ssl when not explicitly overridden' do
        config = plugin.send(:resolve_rpc_config, { 'RpcUser' => 'admin', 'RpcPass' => 'explicit_pass' })
        expect(config[:host]).to eq('10.0.0.1')
        expect(config[:port]).to eq(55553)
        expect(config[:ssl]).to eq(false)
      end

      it 'allows explicit RpcHost to override the introspected host' do
        config = plugin.send(:resolve_rpc_config, { 'RpcHost' => '192.0.2.0', 'RpcUser' => 'admin', 'RpcPass' => 'explicit_pass' })
        expect(config[:host]).to eq('192.0.2.0')
      end

      it 'does not set auto_started_rpc flag' do
        plugin.send(:resolve_rpc_config, { 'RpcUser' => 'admin', 'RpcPass' => 'explicit_pass' })
        expect(plugin.auto_started_rpc).to eq(false)
      end
    end

    describe 'error when only one of RpcUser/RpcPass provided' do
      let(:plugins_collection) do
        instance_double('Msf::PluginManager').tap do |pm|
          allow(pm).to receive(:find).and_return(nil)
          allow(pm).to receive(:load).and_return(true)
        end
      end

      before do
        allow(framework).to receive(:plugins).and_return(plugins_collection)
        allow(Rex::Text).to receive(:rand_text_alphanumeric).with(12).and_return('abcdefghijkl')
      end

      it 'raises an error when RpcUser is provided without RpcPass' do
        expect {
          plugin.send(:validate_options!, { 'RpcUser' => 'msf' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /RpcPass/)
      end

      it 'raises an error when RpcPass is provided without RpcUser' do
        expect {
          plugin.send(:validate_options!, { 'RpcPass' => 'secret' })
        }.to raise_error(Msf::MCP::Config::ValidationError, /RpcUser/)
      end
    end

    describe 'connection to external RPC when RpcHost+RpcPass provided without msgrpc loaded' do
      let(:plugins_collection) do
        instance_double('Msf::PluginManager').tap do |pm|
          allow(pm).to receive(:find).and_return(nil)
          allow(pm).to receive(:load).and_return(true)
        end
      end

      before do
        allow(framework).to receive(:plugins).and_return(plugins_collection)
        allow(Rex::Text).to receive(:rand_text_alphanumeric).with(12).and_return('abcdefghijkl')
      end

      it 'uses the provided RpcHost' do
        config = plugin.send(:resolve_rpc_config, { 'RpcHost' => '192.0.2.0', 'RpcPass' => 'remote_pass' })
        expect(config[:host]).to eq('192.0.2.0')
      end

      it 'uses the provided RpcPass' do
        config = plugin.send(:resolve_rpc_config, { 'RpcHost' => '192.0.2.0', 'RpcPass' => 'remote_pass' })
        expect(config[:pass]).to eq('remote_pass')
      end

      it 'does not auto-start msgrpc when explicit RpcPass is provided' do
        plugin.send(:resolve_rpc_config, { 'RpcHost' => '192.0.2.0', 'RpcPass' => 'remote_pass' })
        expect(plugin.auto_started_rpc).to eq(false)
      end

      it 'does not set auto_started_rpc flag' do
        plugin.send(:resolve_rpc_config, { 'RpcHost' => '192.0.2.0', 'RpcPass' => 'remote_pass' })
        expect(plugin.auto_started_rpc).to eq(false)
      end
    end

    describe 'RpcUser defaults to "msf" when only RpcHost+RpcPass are provided' do
      let(:plugins_collection) do
        instance_double('Msf::PluginManager').tap do |pm|
          allow(pm).to receive(:find).and_return(nil)
          allow(pm).to receive(:load).and_return(true)
        end
      end

      before do
        allow(framework).to receive(:plugins).and_return(plugins_collection)
      end

      it 'defaults RpcUser to "msf"' do
        config = plugin.send(:resolve_rpc_config, { 'RpcHost' => '192.0.2.0', 'RpcPass' => 'remote_pass' })
        expect(config[:user]).to eq('msf')
      end

      it 'uses explicit RpcUser when provided alongside RpcHost+RpcPass' do
        config = plugin.send(:resolve_rpc_config, { 'RpcHost' => '192.0.2.0', 'RpcUser' => 'custom', 'RpcPass' => 'remote_pass' })
        expect(config[:user]).to eq('custom')
      end
    end

    describe 'RpcSSL default and case-insensitive parsing' do
      let(:plugins_collection) do
        instance_double('Msf::PluginManager').tap do |pm|
          allow(pm).to receive(:find).and_return(nil)
          allow(pm).to receive(:load).and_return(true)
        end
      end

      before do
        allow(framework).to receive(:plugins).and_return(plugins_collection)
        allow(Rex::Text).to receive(:rand_text_alphanumeric).with(12).and_return('abcdefghijkl')
      end

      it 'defaults explicit-RPC ssl to Msf::MCP::Config::Defaults::RPC_SSL when RpcSSL is not set' do
        config = plugin.send(:resolve_rpc_config, { 'RpcHost' => '192.0.2.0', 'RpcPass' => 'remote_pass' })
        expect(config[:ssl]).to eq(Msf::MCP::Config::Defaults::RPC_SSL)
      end

      it 'accepts RpcSSL=TRUE on the explicit RPC path (case-insensitive)' do
        config = plugin.send(:resolve_rpc_config,
                             { 'RpcHost' => '192.0.2.0', 'RpcPass' => 'remote_pass', 'RpcSSL' => 'TRUE' })
        expect(config[:ssl]).to eq(true)
      end

      it 'accepts RpcSSL=False on the explicit RPC path (case-insensitive)' do
        config = plugin.send(:resolve_rpc_config,
                             { 'RpcHost' => '192.0.2.0', 'RpcPass' => 'remote_pass', 'RpcSSL' => 'False' })
        expect(config[:ssl]).to eq(false)
      end

      it 'defaults auto-started msgrpc ssl to Msf::MCP::Config::Defaults::RPC_SSL when RpcSSL is not set' do
        config = plugin.send(:resolve_rpc_config, {})
        expect(config[:ssl]).to eq(Msf::MCP::Config::Defaults::RPC_SSL)
      end

      it 'forwards the resolved ssl as a "true"/"false" string to the msgrpc plugin loader' do
        expected = Msf::MCP::Config::Defaults::RPC_SSL.to_s
        expect(plugins_collection).to receive(:load)
          .with('msgrpc', hash_including('SSL' => expected))
        plugin.send(:resolve_rpc_config, {})
      end

      it 'forwards the requested ssl value case-insensitively to the msgrpc plugin loader' do
        expect(plugins_collection).to receive(:load)
          .with('msgrpc', hash_including('SSL' => 'true'))
        plugin.send(:resolve_rpc_config, { 'RpcSSL' => 'TRUE' })
      end
    end

    describe 'RpcSSL case-insensitive parsing on the introspection path' do
      let(:msgrpc_server) do
        instance_double(
          'Msf::RPC::Service',
          srvhost: '127.0.0.1',
          srvport: 55552,
          users: { 'msf' => 'p' },
          options: { ssl: false }
        )
      end

      let(:msgrpc_plugin) do
        instance_double('Msf::Plugin::MSGRPC', name: 'msgrpc', server: msgrpc_server)
      end

      let(:plugins_collection) { [msgrpc_plugin] }

      before do
        allow(framework).to receive(:plugins).and_return(plugins_collection)
      end

      it 'accepts RpcSSL=TRUE and overrides the introspected value' do
        config = plugin.send(:resolve_rpc_config, { 'RpcSSL' => 'TRUE' })
        expect(config[:ssl]).to eq(true)
      end

      it 'accepts RpcSSL=False and overrides the introspected value' do
        config = plugin.send(:resolve_rpc_config, { 'RpcSSL' => 'False' })
        expect(config[:ssl]).to eq(false)
      end
    end
  end
end
