# frozen_string_literal: true

require 'spec_helper'
require 'rex/text'
require Metasploit::Framework.root.join('plugins/mcp.rb').to_path

RSpec.describe Msf::Plugin::MCP::McpCommandDispatcher do
  include_context 'Msf::UIDriver'

  let(:framework) { instance_double(Msf::Framework) }
  let(:output) { driver_output }

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
      def self.generate_auth_token
        'a' * 64
      end

      def initialize(**_args); end

      def start(**_args); end

      def shutdown; end
    end
  end

  let(:plugin) do
    described_class.new(driver).tap do |d|
      d.plugin = mcp_plugin
    end
  end

  let(:base_opts) { { 'LocalOutput' => output } }

  let(:mcp_plugin) { Msf::Plugin::MCP.new(framework, base_opts) }

  before do
    allow(framework).to receive(:threads).and_return(threads_manager)
    allow(framework).to receive(:plugins).and_return(plugins_collection)

    stub_const('Msf::MCP::Metasploit::Client', mock_client_class)
    stub_const('Msf::MCP::Metasploit::AuthenticationError', Class.new(StandardError))
    stub_const('Msf::MCP::Metasploit::ConnectionError', Class.new(StandardError))
    stub_const('Msf::MCP::Security::RateLimiter', mock_rate_limiter_class)
    stub_const('Msf::MCP::Server', mock_server_class)

    allow(Rex::Text).to receive(:rand_text_alphanumeric).with(12).and_return('abcdefghijkl')

    mock_dispatcher = instance_double(described_class)
    allow(mock_dispatcher).to receive(:plugin=)
    allow_any_instance_of(Msf::Plugin::MCP).to receive(:add_console_dispatcher).and_return(mock_dispatcher)
    allow_any_instance_of(Msf::Plugin::MCP).to receive(:remove_console_dispatcher)

    # Capture output from the plugin's print methods
    capture_logging(mcp_plugin)

    allow(mcp_plugin).to receive(:verify_port_available!)
    allow(mcp_plugin).to receive(:verify_mcp_server_started!)
    allow(mcp_plugin).to receive(:verify_msgrpc_started!)
  end

  describe '#name' do
    it 'returns MCP' do
      expect(plugin.name).to eq('MCP')
    end
  end

  describe '#commands' do
    it 'registers the mcp command' do
      expect(plugin.commands).to eq({ 'mcp' => 'Manage the MCP server' })
    end
  end

  describe '#cmd_mcp_tabs' do
    it 'returns all subcommands when typing subcommand' do
      # User typed: "mcp <tab>" → words = ['mcp'], str = ''
      expect(plugin.cmd_mcp_tabs('', ['mcp'])).to contain_exactly('status', 'start', 'stop', 'restart', 'help')
    end

    it 'filters subcommands by partial input' do
      # User typed: "mcp st<tab>" → words = ['mcp'], str = 'st'
      expect(plugin.cmd_mcp_tabs('st', ['mcp'])).to contain_exactly('status', 'start', 'stop')
    end

    it 'returns option completions for start subcommand' do
      # User typed: "mcp start <tab>" → words = ['mcp', 'start'], str = ''
      result = plugin.cmd_mcp_tabs('', ['mcp', 'start'])
      expect(result).to include('ServerHost=', 'RpcHost=', 'RpcPass=')
    end

    it 'returns empty array for status subcommand' do
      # User typed: "mcp status <tab>" → words = ['mcp', 'status'], str = ''
      expect(plugin.cmd_mcp_tabs('', ['mcp', 'status'])).to eq([])
    end
  end

  describe 'mcp status' do
    context 'when server is running with HTTP transport' do
      before do
        mcp_plugin.start_server({})
        reset_logging!
        allow(Time).to receive(:now).and_return(Time.at(1000))
        mcp_plugin.instance_variable_set(:@started_at, Time.at(1000))
      end

      it 'displays running state' do
        mcp_plugin.print_mcp_status
        expect(@output.join("\n")).to include('MCP server status: running')
      end

      it 'displays listening address and port' do
        mcp_plugin.print_mcp_status
        expect(@output.join("\n")).to include('http://localhost:3000')
      end

      it 'displays uptime' do
        mcp_plugin.print_mcp_status
        expect(@output.join("\n")).to include('Uptime:')
      end
    end

    context 'when server is stopped' do
      before do
        mcp_plugin.start_server({})
        mcp_plugin.stop_server
        reset_logging!
      end

      it 'displays stopped state' do
        mcp_plugin.print_mcp_status
        expect(@output.join("\n")).to include('MCP server status: stopped')
      end
    end

    context 'when server is running with custom host and port' do
      before do
        mcp_plugin.start_server('ServerHost' => '0.0.0.0', 'ServerPort' => '8080')
        reset_logging!
        allow(Time).to receive(:now).and_return(Time.at(1000))
        mcp_plugin.instance_variable_set(:@started_at, Time.at(1000))
      end

      it 'displays the custom listening address' do
        mcp_plugin.print_mcp_status
        expect(@output.join("\n")).to include('http://0.0.0.0:8080')
      end
    end

    context 'uptime formatting' do
      before do
        mcp_plugin.start_server({})
        reset_logging!
      end

      it 'formats seconds only' do
        allow(Time).to receive(:now).and_return(Time.at(1045))
        mcp_plugin.instance_variable_set(:@started_at, Time.at(1000))
        mcp_plugin.print_mcp_status
        expect(@output.join("\n")).to include('45s')
      end

      it 'formats minutes and seconds' do
        allow(Time).to receive(:now).and_return(Time.at(1125))
        mcp_plugin.instance_variable_set(:@started_at, Time.at(1000))
        mcp_plugin.print_mcp_status
        expect(@output.join("\n")).to include('2m 5s')
      end

      it 'formats hours, minutes, and seconds' do
        allow(Time).to receive(:now).and_return(Time.at(4661))
        mcp_plugin.instance_variable_set(:@started_at, Time.at(1000))
        mcp_plugin.print_mcp_status
        expect(@output.join("\n")).to include('1h 1m 1s')
      end
    end
  end

  describe 'mcp help' do
    it 'prints usage summary with all subcommands' do
      plugin.cmd_mcp_help
      combined = @output.join("\n")
      expect(combined).to include('status')
      expect(combined).to include('start')
      expect(combined).to include('stop')
      expect(combined).to include('restart')
      expect(combined).to include('help')
    end
  end

  describe '#cmd_mcp routing' do
    it 'routes to help when no subcommand given' do
      expect(plugin).to receive(:cmd_mcp_help)
      plugin.cmd_mcp
    end

    it 'routes to help for unrecognized subcommand' do
      expect(plugin).to receive(:cmd_mcp_help)
      plugin.cmd_mcp('unknown')
    end

    it 'routes to status subcommand' do
      expect(mcp_plugin).to receive(:print_mcp_status)
      plugin.cmd_mcp('status')
    end

    it 'routes to start subcommand' do
      expect(mcp_plugin).to receive(:start_server)
      plugin.cmd_mcp('start')
    end

    it 'routes to stop subcommand' do
      expect(mcp_plugin).to receive(:stop_server)
      plugin.cmd_mcp('stop')
    end

    it 'routes to restart subcommand' do
      expect(mcp_plugin).to receive(:restart_server)
      plugin.cmd_mcp('restart')
    end
  end

  describe 'mcp start' do
    context 'when server is stopped' do
      it 'starts the server successfully' do
        mcp_plugin.start_server({})
        expect(@output.join("\n")).to include('MCP server listening')
      end

      it 'sets the server instance' do
        mcp_plugin.start_server({})
        expect(mcp_plugin.mcp_server).not_to be_nil
      end
    end

    context 'when server is already running' do
      before { mcp_plugin.start_server({}) }

      it 'prints an error that server is already running' do
        reset_logging!
        mcp_plugin.start_server({})
        expect(@error.join("\n")).to include('already running')
      end
    end
  end

  describe 'mcp stop' do
    context 'when server is running' do
      before do
        mcp_plugin.start_server({})
        reset_logging!
      end

      it 'stops the server and prints confirmation' do
        mcp_plugin.stop_server
        expect(@output.join("\n")).to include('MCP server stopped')
      end

      it 'clears the server instance' do
        mcp_plugin.stop_server
        expect(mcp_plugin.mcp_server).to be_nil
      end
    end

    context 'when server is already stopped' do
      it 'prints an error that server is already stopped' do
        mcp_plugin.stop_server
        expect(@error.join("\n")).to include('already stopped')
      end
    end
  end

  describe 'mcp restart' do
    context 'when server is running' do
      before { mcp_plugin.start_server({}) }

      it 'stops and then starts the server' do
        mcp_plugin.restart_server({})
        expect(mcp_plugin.mcp_server).not_to be_nil
      end

      it 'resets the started_at timestamp' do
        allow(Time).to receive(:now).and_return(Time.at(2000))
        mcp_plugin.restart_server({})
        expect(mcp_plugin.started_at).to eq(Time.at(2000))
      end
    end

    context 'when server is stopped' do
      it 'starts the server' do
        mcp_plugin.restart_server({})
        expect(mcp_plugin.mcp_server).not_to be_nil
      end
    end
  end
end
