# frozen_string_literal: true

require 'spec_helper'
require 'rex/text'
require Metasploit::Framework.root.join('plugins/mcp.rb').to_path

RSpec.describe Msf::Plugin::MCP do
  include_context 'Msf::UIDriver'

  let(:framework) { instance_double(Msf::Framework) }
  let(:framework_datastore) { { 'VERBOSE' => false } }
  let(:output) { driver_output }
  let(:base_opts) { { 'LocalOutput' => output } }

  let(:mock_thread) do
    instance_double(Thread, alive?: false, join: true, kill: nil)
  end

  let(:threads_manager) do
    instance_double('Msf::Framework::ThreadManager').tap do |tm|
      allow(tm).to receive(:spawn).and_return(mock_thread)
    end
  end

  let(:plugins_collection) do
    instance_double('Msf::PluginManager').tap do |pm|
      allow(pm).to receive(:find).and_return(nil)
      allow(pm).to receive(:load).and_return(true)
      allow(pm).to receive(:unload).and_return(true)
    end
  end

  let(:mock_client_class) do
    Class.new do
      def initialize(**_args); end

      def authenticate(*_args)
        'token'
      end
    end
  end

  let(:mock_rate_limiter_class) do
    Class.new do
      def initialize(**_args); end
    end
  end

  let(:mock_server_class) do
    Class.new do
      def initialize(**_args); end
      def start(**_args); end
      def shutdown; end
    end
  end

  before do
    allow(framework).to receive(:threads).and_return(threads_manager)
    allow(framework).to receive(:plugins).and_return(plugins_collection)
    allow(framework).to receive(:datastore).and_return(framework_datastore)

    stub_const('Msf::MCP::Metasploit::Client', mock_client_class)
    stub_const('Msf::MCP::Metasploit::AuthenticationError', Class.new(StandardError))
    stub_const('Msf::MCP::Metasploit::ConnectionError', Class.new(StandardError))
    stub_const('Msf::MCP::Security::RateLimiter', mock_rate_limiter_class)
    stub_const('Msf::MCP::Server', mock_server_class)

    allow(Rex::Text).to receive(:rand_text_alphanumeric).with(12).and_return('abcdefghijkl')
    allow_any_instance_of(described_class).to receive(:sleep)

    mock_dispatcher = instance_double(Msf::Plugin::MCP::McpCommandDispatcher)
    allow(mock_dispatcher).to receive(:plugin=)
    allow_any_instance_of(Msf::Plugin::MCP).to receive(:add_console_dispatcher).and_return(mock_dispatcher)
    allow_any_instance_of(Msf::Plugin::MCP).to receive(:remove_console_dispatcher)
  end

  describe '#initialize' do
    subject(:plugin) { described_class.new(framework, base_opts) }

    it 'creates the plugin successfully without starting the server' do
      expect { plugin }.not_to raise_error
    end

    it 'does not create an MCP client' do
      expect(mock_client_class).not_to receive(:new)
      plugin
    end

    it 'does not spawn a server thread' do
      expect(threads_manager).not_to receive(:spawn)
      plugin
    end

    it 'prints a message about using mcp start' do
      plugin
      expect(@output.join("\n")).to include('mcp start')
    end

    it 'registers the command dispatcher' do
      expect_any_instance_of(described_class).to receive(:add_console_dispatcher)
        .with(described_class::McpCommandDispatcher)
        .and_return(instance_double(described_class::McpCommandDispatcher, :plugin= => nil))
      plugin
    end

    it 'has nil server_config' do
      expect(plugin.server_config).to be_nil
    end
  end

  describe '#start_server' do
    subject(:plugin) { described_class.new(framework, base_opts) }

    context 'with default options' do
      before { plugin.start_server({}) }

      it 'creates an MCP client' do
        expect(plugin.msf_client).not_to be_nil
      end

      it 'starts the server in a background thread' do
        expect(threads_manager).to have_received(:spawn).with('MCPServer', false)
      end

      it 'prints a status message with the listening address' do
        expect(@output.join("\n")).to include('MCP server started on localhost:3000 (transport: http)')
      end

      it 'stores the server configuration' do
        expect(plugin.server_config).to be_a(Hash)
        expect(plugin.server_config[:mcp][:transport]).to eq('http')
      end
    end

    context 'with custom options' do
      before { plugin.start_server('ServerHost' => '0.0.0.0', 'ServerPort' => '8080') }

      it 'applies the provided host and port' do
        expect(plugin.server_config[:mcp][:host]).to eq('0.0.0.0')
        expect(plugin.server_config[:mcp][:port]).to eq(8080)
      end
    end

    context 'with stdio transport' do
      it 'rejects stdio since it is not supported from msfconsole' do
        plugin.start_server('Transport' => 'stdio')
        expect(@error.join("\n")).to include('Invalid value for Transport')
      end
    end

    context 'when server is already running' do
      before do
        plugin.start_server({})
        reset_logging!
      end

      it 'prints an error and does not restart' do
        plugin.start_server({})
        expect(@error.join("\n")).to include('MCP server is already running')
      end
    end

    context 'when port is already in use' do
      let(:failing_server_class) do
        Class.new do
          def initialize(**_args); end

          def start(**_args)
            raise Errno::EADDRINUSE
          end

          def shutdown; end
        end
      end

      before do
        stub_const('Msf::MCP::Server', failing_server_class)
        allow(threads_manager).to receive(:spawn) do |_name, _critical, &block|
          block.call
        end
      end

      it 'prints an error with address-in-use message' do
        plugin.start_server({})
        expect(@error.join("\n")).to include('Address already in use')
      end
    end

    context 'when RPC authentication fails' do
      let(:failing_client_class) do
        error_class = Msf::MCP::Metasploit::AuthenticationError
        Class.new do
          define_method(:initialize) { |**_args| }
          define_method(:authenticate) { |*_args| raise error_class, 'bad credentials' }
        end
      end

      before do
        stub_const('Msf::MCP::Metasploit::Client', failing_client_class)
      end

      it 'prints an error with authentication failure message' do
        plugin.start_server({})
        expect(@error.join("\n")).to include('RPC authentication failed')
      end
    end

    context 'when RPC connection fails' do
      let(:failing_client_class) do
        error_class = Msf::MCP::Metasploit::ConnectionError
        Class.new do
          define_method(:initialize) { |**_args| }
          define_method(:authenticate) { |*_args| raise error_class, 'connection refused' }
        end
      end

      before do
        stub_const('Msf::MCP::Metasploit::Client', failing_client_class)
      end

      it 'prints an error with connection failure message' do
        plugin.start_server({})
        expect(@error.join("\n")).to include('RPC connection failed')
      end

      it 'unloads the auto-started msgrpc plugin on failure' do
        msgrpc_plugin = instance_double('Msf::Plugin::MSGRPC', name: 'msgrpc')
        call_count = 0
        allow(plugins_collection).to receive(:find) do
          call_count += 1
          call_count > 1 ? msgrpc_plugin : nil
        end
        expect(plugins_collection).to receive(:unload).with(msgrpc_plugin)
        plugin.start_server({})
      end
    end
  end

  describe '#stop_server' do
    subject(:plugin) { described_class.new(framework, base_opts) }

    context 'when server is running' do
      before do
        plugin.start_server({})
        reset_logging!
      end

      it 'stops the server and prints a message' do
        plugin.stop_server
        expect(@output.join("\n")).to include('MCP server stopped')
      end

      it 'nils out the server reference' do
        plugin.stop_server
        expect(plugin.mcp_server).to be_nil
      end

      it 'nils out the client reference' do
        plugin.stop_server
        expect(plugin.msf_client).to be_nil
      end
    end

    context 'when server is not running' do
      it 'prints an error' do
        plugin.stop_server
        expect(@error.join("\n")).to include('MCP server is already stopped')
      end
    end
  end

  describe '#restart_server' do
    subject(:plugin) { described_class.new(framework, base_opts) }

    context 'when server is running' do
      before do
        plugin.start_server({})
        reset_logging!
      end

      it 'restarts with new options' do
        plugin.restart_server('ServerPort' => '9090')
        expect(plugin.server_config[:mcp][:port]).to eq(9090)
      end
    end

    context 'when server is not running' do
      it 'starts the server fresh' do
        plugin.restart_server('ServerPort' => '8080')
        expect(plugin.server_config[:mcp][:port]).to eq(8080)
        expect(plugin.mcp_server).not_to be_nil
      end
    end
  end

  describe '#print_mcp_status' do
    subject(:plugin) { described_class.new(framework, base_opts) }

    context 'when server has never been configured' do
      it 'prints not configured status' do
        plugin.print_mcp_status
        expect(@output.join("\n")).to include('stopped (not configured)')
      end
    end

    context 'when server is running' do
      before do
        plugin.start_server({})
        reset_logging!
      end

      it 'prints running status with details' do
        plugin.print_mcp_status
        combined = @output.join("\n")
        expect(combined).to include('MCP server status: running')
        expect(combined).to include('Transport: http')
        expect(combined).to include('http://localhost:3000')
      end
    end

    context 'when server was started then stopped' do
      before do
        plugin.start_server({})
        plugin.stop_server
        reset_logging!
      end

      it 'prints stopped status with last known config' do
        plugin.print_mcp_status
        combined = @output.join("\n")
        expect(combined).to include('MCP server status: stopped')
        expect(combined).to include('Transport: http')
      end
    end
  end

  describe '#cleanup' do
    subject(:plugin) { described_class.new(framework, base_opts) }

    before do
      allow(plugin).to receive(:remove_console_dispatcher)
    end

    context 'when server is running' do
      before do
        plugin.start_server({})
        reset_logging!
      end

      it 'shuts down the MCP server' do
        server = plugin.mcp_server
        expect(server).to receive(:shutdown)
        plugin.cleanup
      end

      it 'prints a stop message' do
        plugin.cleanup
        expect(@output.join("\n")).to include('MCP server stopped')
      end

      it 'nils out all references' do
        plugin.cleanup
        expect(plugin.mcp_server).to be_nil
        expect(plugin.server_thread).to be_nil
        expect(plugin.msf_client).to be_nil
        expect(plugin.rate_limiter).to be_nil
        expect(plugin.started_at).to be_nil
      end
    end

    context 'when server was never started' do
      it 'deregisters the console dispatcher without error' do
        expect(plugin).to receive(:remove_console_dispatcher).with('MCP')
        expect { plugin.cleanup }.not_to raise_error
      end
    end

    context 'when msgrpc was auto-started' do
      before { plugin.start_server({}) }

      it 'unloads the auto-started msgrpc plugin' do
        plugin.auto_started_rpc = true
        msgrpc_plugin = instance_double('Msf::Plugin::MSGRPC', name: 'msgrpc')
        allow(plugins_collection).to receive(:find).and_return(msgrpc_plugin)
        expect(plugins_collection).to receive(:unload).with(msgrpc_plugin)
        plugin.cleanup
      end
    end

    context 'when msgrpc was pre-existing' do
      before { plugin.start_server({}) }

      it 'does not unload the msgrpc plugin' do
        plugin.auto_started_rpc = false
        expect(plugins_collection).not_to receive(:unload)
        plugin.cleanup
      end
    end

    context 'when msgrpc unload fails' do
      before { plugin.start_server({}) }

      it 'prints a warning and continues cleanup' do
        plugin.auto_started_rpc = true
        msgrpc_plugin = instance_double('Msf::Plugin::MSGRPC', name: 'msgrpc')
        allow(plugins_collection).to receive(:find).and_return(msgrpc_plugin)
        allow(plugins_collection).to receive(:unload).and_raise(StandardError, 'unload failed')

        plugin.cleanup

        expect(@error.join("\n")).to include('Failed to unload auto-started msgrpc')
        expect(plugin.mcp_server).to be_nil
      end
    end
  end

  describe '#terminate_server_thread' do
    subject(:plugin) { described_class.new(framework, base_opts) }

    context 'when thread terminates within 5 seconds' do
      it 'does not force kill the thread' do
        alive_thread = instance_double(Thread, alive?: true, join: true)
        plugin.server_thread = alive_thread
        expect(alive_thread).not_to receive(:kill)
        plugin.send(:terminate_server_thread)
      end
    end

    context 'when thread does not terminate within 5 seconds' do
      it 'force kills the thread' do
        stuck_thread = instance_double(Thread, alive?: true, join: nil, kill: nil)
        plugin.server_thread = stuck_thread
        expect(stuck_thread).to receive(:kill)
        plugin.send(:terminate_server_thread)
      end

      it 'prints a warning message' do
        stuck_thread = instance_double(Thread, alive?: true, join: nil, kill: nil)
        plugin.server_thread = stuck_thread
        plugin.send(:terminate_server_thread)
        expect(@error.join("\n")).to include('did not terminate gracefully')
      end
    end

    context 'when thread is already dead' do
      it 'does nothing' do
        dead_thread = instance_double(Thread, alive?: false)
        plugin.server_thread = dead_thread
        expect(dead_thread).not_to receive(:join)
        expect(dead_thread).not_to receive(:kill)
        plugin.send(:terminate_server_thread)
      end
    end

    context 'when server_thread is nil' do
      it 'does nothing' do
        plugin.server_thread = nil
        expect { plugin.send(:terminate_server_thread) }.not_to raise_error
      end
    end
  end

  describe 'RPC resolution' do
    subject(:plugin) { described_class.new(framework, base_opts) }

    context 'with explicit RPC credentials' do
      it 'uses the provided credentials' do
        plugin.start_server('RpcUser' => 'admin', 'RpcPass' => 'secret123')
        expect(plugin.server_config[:rpc][:user]).to eq('admin')
        expect(plugin.server_config[:rpc][:pass]).to eq('secret123')
      end
    end

    context 'when msgrpc is already loaded (introspection path)' do
      let(:mock_msgrpc_server) do
        instance_double('Msf::RPC::Service').tap do |s|
          allow(s).to receive(:users).and_return({ 'admin' => 'secretpass' })
          allow(s).to receive(:srvhost).and_return('127.0.0.1')
          allow(s).to receive(:srvport).and_return(55_553)
          allow(s).to receive(:options).and_return({ ssl: true })
        end
      end

      let(:mock_msgrpc_plugin) do
        instance_double('Msf::Plugin::MSGRPC', name: 'msgrpc', server: mock_msgrpc_server)
      end

      before do
        allow(plugins_collection).to receive(:find) do |&block|
          [mock_msgrpc_plugin].find(&block)
        end
      end

      it 'uses credentials from the loaded msgrpc plugin' do
        plugin.start_server({})
        expect(plugin.server_config[:rpc][:user]).to eq('admin')
        expect(plugin.server_config[:rpc][:pass]).to eq('secretpass')
      end

      it 'uses host and port from the loaded msgrpc plugin' do
        plugin.start_server({})
        expect(plugin.server_config[:rpc][:host]).to eq('127.0.0.1')
        expect(plugin.server_config[:rpc][:port]).to eq(55_553)
      end

      it 'does not auto-start msgrpc' do
        expect(plugins_collection).not_to receive(:load)
        plugin.start_server({})
      end

      it 'does not set auto_started_rpc flag' do
        plugin.start_server({})
        expect(plugin.auto_started_rpc).to be false
      end
    end

    context 'when no msgrpc is loaded and no creds provided (auto-start path)' do
      it 'auto-starts msgrpc and prints credentials' do
        expect(plugins_collection).to receive(:load).with('msgrpc', hash_including('Pass' => 'abcdefghijkl', 'User' => 'msf'))
        plugin.start_server({})
        expect(@output.join("\n")).to include('Auto-started msgrpc')
        expect(@output.join("\n")).to include('abcdefghijkl')
      end

      it 'sets auto_started_rpc flag' do
        plugin.start_server({})
        expect(plugin.auto_started_rpc).to be true
      end
    end
  end

  describe 'option validation' do
    subject(:plugin) { described_class.new(framework, base_opts) }

    context 'with invalid ServerPort' do
      it 'prints an error' do
        plugin.start_server('ServerPort' => '99999')
        expect(@error.join("\n")).to include('Invalid value for ServerPort')
      end
    end

    context 'with invalid Transport' do
      it 'prints an error for unsupported transport' do
        plugin.start_server('Transport' => 'websocket')
        expect(@error.join("\n")).to include('Invalid value for Transport')
      end

      it 'prints an error for stdio transport' do
        plugin.start_server('Transport' => 'stdio')
        expect(@error.join("\n")).to include('Invalid value for Transport')
      end
    end

    context 'with invalid RpcSSL' do
      it 'prints an error' do
        plugin.start_server('RpcSSL' => 'maybe')
        expect(@error.join("\n")).to include('Invalid value for RpcSSL')
      end
    end

    context 'with invalid RateLimit' do
      it 'prints an error' do
        plugin.start_server('RateLimit' => '0')
        expect(@error.join("\n")).to include('Invalid value for RateLimit')
      end
    end

    context 'with RpcUser but no RpcPass' do
      it 'prints an error' do
        plugin.start_server('RpcUser' => 'admin')
        expect(@error.join("\n")).to include('Invalid value for RpcPass')
      end
    end

    context 'with RpcPass but no RpcUser' do
      it 'prints an error' do
        plugin.start_server('RpcPass' => 'secret')
        expect(@error.join("\n")).to include('Invalid value for RpcUser')
      end
    end
  end

  describe Msf::Plugin::MCP::McpCommandDispatcher do
    let(:plugin_instance) { Msf::Plugin::MCP.new(framework, base_opts) }
    let(:dispatcher) do
      d = Msf::Plugin::MCP::McpCommandDispatcher.new(driver)
      d.plugin = plugin_instance
      d
    end

    before do
      capture_logging(dispatcher)
    end

    describe '#cmd_mcp with start subcommand' do
      it 'parses Key=Value options and passes them to start_server' do
        expect(plugin_instance).to receive(:start_server) do |opts|
          expect(opts).to eq('Transport' => 'http', 'RateLimit' => '120')
        end
        dispatcher.cmd_mcp('start', 'Transport=http', 'RateLimit=120')
      end

      it 'starts with empty opts when no options given' do
        expect(plugin_instance).to receive(:start_server) do |opts|
          expect(opts).to eq({})
        end
        dispatcher.cmd_mcp('start')
      end

      it 'rejects malformed options' do
        expect(plugin_instance).not_to receive(:start_server)
        dispatcher.cmd_mcp('start', 'badoption')
        expect(@error.join("\n")).to include('Invalid option format')
      end

      it 'rejects unknown option keys' do
        expect(plugin_instance).not_to receive(:start_server)
        dispatcher.cmd_mcp('start', 'FakeOption=value')
        expect(@error.join("\n")).to include('Unknown option: FakeOption')
      end
    end

    describe '#cmd_mcp with restart subcommand' do
      it 'parses options and passes them to restart_server' do
        expect(plugin_instance).to receive(:restart_server) do |opts|
          expect(opts).to eq('ServerPort' => '9090')
        end
        dispatcher.cmd_mcp('restart', 'ServerPort=9090')
      end
    end

    describe '#cmd_mcp with help subcommand' do
      it 'prints usage information including option examples' do
        dispatcher.cmd_mcp('help')
        combined = @output.join("\n")
        expect(combined).to include('Usage: mcp <subcommand> [options]')
        expect(combined).to include('Transport=<http>')
        expect(combined).to include('mcp start RpcUser=msf RpcPass=secret')
      end
    end

    describe '#cmd_mcp_tabs' do
      it 'returns subcommands for first word' do
        result = dispatcher.cmd_mcp_tabs('', [''])
        expect(result).to contain_exactly('status', 'start', 'stop', 'restart', 'help')
      end

      it 'returns empty for subsequent words' do
        result = dispatcher.cmd_mcp_tabs('', %w[start something])
        expect(result).to eq([])
      end
    end
  end
end
