# frozen_string_literal: true

require 'msf/core/mcp'
require 'socket'
require 'stringio'

RSpec.describe Msf::MCP::RpcManager do
  let(:output) { StringIO.new }
  let(:default_config) do
    {
      msf_api: {
        type: 'messagepack',
        host: 'localhost',
        port: 55553,
        ssl: true,
        endpoint: '/api/',
        user: 'testuser',
        password: 'testpass',
        auto_start_rpc: true
      }
    }
  end

  describe '#initialize' do
    it 'initializes with config and output' do
      manager = described_class.new(config: default_config, output: output)
      expect(manager).to be_a(described_class)
    end

    it 'is not managing an RPC server initially' do
      manager = described_class.new(config: default_config, output: output)
      expect(manager.rpc_managed?).to be false
    end

    it 'has no rpc_pid initially' do
      manager = described_class.new(config: default_config, output: output)
      expect(manager.rpc_pid).to be_nil
    end
  end

  describe '#rpc_available?' do
    let(:manager) { described_class.new(config: default_config, output: output) }

    context 'when RPC server is listening' do
      it 'returns true' do
        tcp_socket = instance_double('Rex::Socket::Tcp')
        allow(Rex::Socket::Tcp).to receive(:create).with(
          'PeerHost' => 'localhost',
          'PeerPort' => 55553
        ).and_return(tcp_socket)
        allow(tcp_socket).to receive(:close)

        expect(manager.rpc_available?).to be true
      end

      it 'closes the probe connection' do
        tcp_socket = instance_double('Rex::Socket::Tcp')
        allow(Rex::Socket::Tcp).to receive(:create).with(
          'PeerHost' => 'localhost',
          'PeerPort' => 55553
        ).and_return(tcp_socket)
        expect(tcp_socket).to receive(:close)

        manager.rpc_available?
      end
    end

    context 'when RPC server is not listening' do
      it 'returns false on connection refused' do
        allow(Rex::Socket::Tcp).to receive(:create).and_raise(Rex::ConnectionError)

        expect(manager.rpc_available?).to be false
      end

      it 'returns false on host unreachable' do
        allow(Rex::Socket::Tcp).to receive(:create).and_raise(Rex::ConnectionError)

        expect(manager.rpc_available?).to be false
      end

      it 'returns false on network unreachable' do
        allow(Rex::Socket::Tcp).to receive(:create).and_raise(Rex::ConnectionError)

        expect(manager.rpc_available?).to be false
      end

      it 'returns false on socket error' do
        allow(Rex::Socket::Tcp).to receive(:create).and_raise(Rex::ConnectionError)

        expect(manager.rpc_available?).to be false
      end

      it 'returns false on timeout' do
        allow(Rex::Socket::Tcp).to receive(:create).and_raise(Rex::ConnectionError)

        expect(manager.rpc_available?).to be false
      end
    end

    context 'with custom host and port' do
      let(:custom_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(host: '192.0.2.1', port: 9999)
        config
      end
      let(:manager) { described_class.new(config: custom_config, output: output) }

      it 'probes the configured host and port' do
        expect(Rex::Socket::Tcp).to receive(:create).with(
          'PeerHost' => '192.0.2.1',
          'PeerPort' => 9999
        ).and_raise(Rex::ConnectionError)

        manager.rpc_available?
      end
    end
  end

  describe '#auto_start_enabled?' do
    context 'when auto_start_rpc is true in config' do
      it 'returns true' do
        manager = described_class.new(config: default_config, output: output)
        expect(manager.auto_start_enabled?).to be true
      end
    end

    context 'when auto_start_rpc is false in config' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(auto_start_rpc: false)
        manager = described_class.new(config: config, output: output)

        expect(manager.auto_start_enabled?).to be false
      end
    end

    context 'when host is not localhost' do
      it 'returns false for remote host' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(host: '192.0.2.1')
        manager = described_class.new(config: config, output: output)

        expect(manager.auto_start_enabled?).to be false
      end

      it 'returns false for remote hostname' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(host: 'remote.example.com')
        manager = described_class.new(config: config, output: output)

        expect(manager.auto_start_enabled?).to be false
      end
    end

    context 'when host is localhost variants' do
      it 'returns true for localhost' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(host: 'localhost')
        manager = described_class.new(config: config, output: output)

        expect(manager.auto_start_enabled?).to be true
      end

      it 'returns true for 127.0.0.1' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(host: '127.0.0.1')
        manager = described_class.new(config: config, output: output)

        expect(manager.auto_start_enabled?).to be true
      end

      it 'returns true for ::1 (IPv6 loopback)' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(host: '::1')
        manager = described_class.new(config: config, output: output)

        expect(manager.auto_start_enabled?).to be true
      end
    end

    context 'when api type is json-rpc' do
      it 'returns false (JSON-RPC auto-start not supported)' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(type: 'json-rpc', token: 'tok123')
        manager = described_class.new(config: config, output: output)

        expect(manager.auto_start_enabled?).to be false
      end
    end
  end

  describe '#start_rpc_server' do
    let(:manager) { described_class.new(config: default_config, output: output) }

    context 'when msfrpcd is available' do
      before do
        allow(File).to receive(:executable?).with(Msf::MCP::RpcManager::MSFRPCD_PATH).and_return(true)
        allow(Process).to receive(:spawn).and_return(67890)
      end

      it 'spawns msfrpcd' do
        expect(Process).to receive(:spawn)
        manager.start_rpc_server
      end

      it 'sets the rpc_pid' do
        manager.start_rpc_server
        expect(manager.rpc_pid).to eq(67890)
      end

      it 'marks the RPC server as managed' do
        manager.start_rpc_server
        expect(manager.rpc_managed?).to be true
      end

      it 'passes credentials via environment variables' do
        expect(Process).to receive(:spawn).with(
          hash_including('MSF_RPC_USER' => 'testuser', 'MSF_RPC_PASS' => 'testpass'),
          anything,
          any_args
        ).and_return(67890)

        manager.start_rpc_server
      end

      it 'does not pass credentials as command-line arguments' do
        expect(Process).to receive(:spawn) do |_env, _path, *cmd_args|
          flat = cmd_args.flatten
          expect(flat).not_to include('testuser')
          expect(flat).not_to include('testpass')
          expect(flat).not_to include('-U')
          expect(flat).not_to include('-P')
        end.and_return(67890)

        manager.start_rpc_server
      end

      it 'passes the configured host to msfrpcd' do
        expect(Process).to receive(:spawn) do |_env, _path, *cmd_args|
          expect(cmd_args.flatten).to include('-a', 'localhost')
        end.and_return(67890)

        manager.start_rpc_server
      end

      it 'passes the configured port to msfrpcd' do
        expect(Process).to receive(:spawn) do |_env, _path, *cmd_args|
          expect(cmd_args.flatten).to include('-p', '55553')
        end.and_return(67890)

        manager.start_rpc_server
      end

      it 'passes the foreground flag to msfrpcd' do
        expect(Process).to receive(:spawn) do |_env, _path, *cmd_args|
          expect(cmd_args.flatten).to include('-f')
        end.and_return(67890)

        manager.start_rpc_server
      end

      it 'outputs a status message with PID' do
        manager.start_rpc_server
        expect(output.string).to include('msfrpcd')
        expect(output.string).to include('67890')
      end
    end

    context 'when msfrpcd is not found' do
      before do
        allow(File).to receive(:executable?).with(Msf::MCP::RpcManager::MSFRPCD_PATH).and_return(false)
      end

      it 'raises an RpcStartupError' do
        expect { manager.start_rpc_server }.to raise_error(
          Msf::MCP::Metasploit::RpcStartupError, /msfrpcd.*not found/i
        )
      end

      it 'does not set rpc_pid' do
        begin
          manager.start_rpc_server
        rescue Msf::MCP::Metasploit::RpcStartupError
          # expected
        end
        expect(manager.rpc_pid).to be_nil
      end
    end

    context 'when already managing an RPC server' do
      before do
        allow(File).to receive(:executable?).with(Msf::MCP::RpcManager::MSFRPCD_PATH).and_return(true)
        allow(Process).to receive(:spawn).and_return(12345)
        manager.start_rpc_server
      end

      it 'does not start a second RPC server' do
        expect(Process).not_to receive(:spawn)
        manager.start_rpc_server
      end

      it 'outputs a message that RPC is already managed' do
        manager.start_rpc_server
        expect(output.string).to include('already')
      end
    end
  end

  describe '#wait_for_rpc' do
    let(:manager) { described_class.new(config: default_config, output: output) }

    context 'when RPC becomes available immediately' do
      before do
        allow(manager).to receive(:rpc_available?).and_return(true)
      end

      it 'returns true' do
        expect(manager.wait_for_rpc(timeout: 10)).to be true
      end

      it 'outputs a success message' do
        manager.wait_for_rpc(timeout: 10)
        expect(output.string).to include('RPC server is ready')
      end
    end

    context 'when RPC becomes available after retries' do
      before do
        call_count = 0
        allow(manager).to receive(:rpc_available?) do
          call_count += 1
          call_count >= 3
        end
        # Stub sleep to avoid actual delays in tests
        allow(manager).to receive(:sleep)
      end

      it 'returns true after retrying' do
        expect(manager.wait_for_rpc(timeout: 30)).to be true
      end

      it 'outputs waiting messages' do
        manager.wait_for_rpc(timeout: 30)
        expect(output.string).to include('Waiting for RPC server')
      end
    end

    context 'when RPC never becomes available' do
      before do
        allow(manager).to receive(:rpc_available?).and_return(false)
        allow(manager).to receive(:sleep)
        # Make Time.now advance to simulate timeout
        start_time = Time.now
        call_count = 0
        allow(Time).to receive(:now) do
          call_count += 1
          start_time + (call_count * 2)
        end
      end

      it 'raises ConnectionError after timeout' do
        expect { manager.wait_for_rpc(timeout: 5) }.to raise_error(
          Msf::MCP::Metasploit::ConnectionError, /timed out/i
        )
      end
    end

    context 'when the managed RPC process dies during wait' do
      before do
        allow(manager).to receive(:rpc_available?).and_return(false)
        allow(manager).to receive(:sleep)
        manager.instance_variable_set(:@rpc_pid, 99999)
        manager.instance_variable_set(:@rpc_managed, true)

        # Simulate process dying: waitpid returns the pid (non-blocking check)
        allow(Process).to receive(:waitpid).with(99999, Process::WNOHANG).and_return(99999)
      end

      it 'raises RpcStartupError indicating the process exited' do
        expect { manager.wait_for_rpc(timeout: 30) }.to raise_error(
          Msf::MCP::Metasploit::RpcStartupError, /exited|died|crashed/i
        )
      end
    end

    context 'with default timeout' do
      before do
        allow(manager).to receive(:rpc_available?).and_return(true)
      end

      it 'uses a reasonable default timeout' do
        # Should not raise and use the default timeout
        expect { manager.wait_for_rpc }.not_to raise_error
      end
    end
  end

  describe '#stop_rpc_server' do
    let(:manager) { described_class.new(config: default_config, output: output) }

    context 'when managing an RPC server' do
      before do
        manager.instance_variable_set(:@rpc_pid, 12345)
        manager.instance_variable_set(:@rpc_managed, true)
      end

      it 'sends SIGTERM to the RPC process' do
        allow(Process).to receive(:kill).with('TERM', 12345)
        allow(Process).to receive(:waitpid).with(12345, anything).and_return(12345)

        expect(Process).to receive(:kill).with('TERM', 12345)
        manager.stop_rpc_server
      end

      it 'waits for the process to exit' do
        allow(Process).to receive(:kill).with('TERM', 12345)
        expect(Process).to receive(:waitpid).with(12345, anything).and_return(12345)

        manager.stop_rpc_server
      end

      it 'clears the rpc_pid after stopping' do
        allow(Process).to receive(:kill).with('TERM', 12345)
        allow(Process).to receive(:waitpid).with(12345, anything).and_return(12345)

        manager.stop_rpc_server
        expect(manager.rpc_pid).to be_nil
      end

      it 'marks the RPC server as no longer managed' do
        allow(Process).to receive(:kill).with('TERM', 12345)
        allow(Process).to receive(:waitpid).with(12345, anything).and_return(12345)

        manager.stop_rpc_server
        expect(manager.rpc_managed?).to be false
      end

      it 'outputs a status message' do
        allow(Process).to receive(:kill).with('TERM', 12345)
        allow(Process).to receive(:waitpid).with(12345, anything).and_return(12345)

        manager.stop_rpc_server
        expect(output.string).to include('Stopping')
      end

      it 'handles process already dead (Errno::ESRCH)' do
        allow(Process).to receive(:kill).with('TERM', 12345).and_raise(Errno::ESRCH)

        expect { manager.stop_rpc_server }.not_to raise_error
        expect(manager.rpc_managed?).to be false
        expect(manager.rpc_pid).to be_nil
      end

      it 'handles permission error (Errno::EPERM)' do
        allow(Process).to receive(:kill).with('TERM', 12345).and_raise(Errno::EPERM)

        expect { manager.stop_rpc_server }.not_to raise_error
        expect(output.string).to include('permission')
      end

      it 'sends SIGKILL if process does not exit after grace period' do
        allow(manager).to receive(:sleep)
        allow(Process).to receive(:waitpid).with(12345, Process::WNOHANG).and_return(nil, nil)
        allow(Process).to receive(:waitpid).with(12345, 0).and_return(12345)

        expect(Process).to receive(:kill).with('TERM', 12345).ordered
        expect(Process).to receive(:kill).with('KILL', 12345).ordered

        manager.stop_rpc_server
      end
    end

    context 'when not managing an RPC server' do
      it 'is a no-op' do
        expect(Process).not_to receive(:kill)
        manager.stop_rpc_server
      end

      it 'does not output any message' do
        manager.stop_rpc_server
        expect(output.string).to be_empty
      end
    end

    context 'when rpc_pid is set but rpc_managed is false' do
      before do
        manager.instance_variable_set(:@rpc_pid, 12345)
        manager.instance_variable_set(:@rpc_managed, false)
      end

      it 'does not attempt to kill the process' do
        expect(Process).not_to receive(:kill)
        manager.stop_rpc_server
      end
    end
  end

  describe '#rpc_managed?' do
    let(:manager) { described_class.new(config: default_config, output: output) }

    it 'returns false initially' do
      expect(manager.rpc_managed?).to be false
    end

    it 'returns true after starting an RPC server' do
      allow(File).to receive(:executable?).with(Msf::MCP::RpcManager::MSFRPCD_PATH).and_return(true)
      allow(Process).to receive(:spawn).and_return(12345)
      manager.start_rpc_server

      expect(manager.rpc_managed?).to be true
    end

    it 'returns false after stopping the RPC server' do
      manager.instance_variable_set(:@rpc_pid, 12345)
      manager.instance_variable_set(:@rpc_managed, true)

      allow(Process).to receive(:kill)
      allow(Process).to receive(:waitpid).and_return(12345)

      manager.stop_rpc_server
      expect(manager.rpc_managed?).to be false
    end
  end

  describe '#rpc_pid' do
    let(:manager) { described_class.new(config: default_config, output: output) }

    it 'returns nil initially' do
      expect(manager.rpc_pid).to be_nil
    end

    it 'returns the PID after starting' do
      allow(File).to receive(:executable?).with(Msf::MCP::RpcManager::MSFRPCD_PATH).and_return(true)
      allow(Process).to receive(:spawn).and_return(54321)
      manager.start_rpc_server

      expect(manager.rpc_pid).to eq(54321)
    end
  end

  describe 'logging' do
    let(:log_file) { Tempfile.new('rpc_manager_log').tap(&:close).path }
    let(:manager) { described_class.new(config: default_config, output: output) }

    before do
      if log_source_registered?(Msf::MCP::LOG_SOURCE)
        deregister_log_source(Msf::MCP::LOG_SOURCE)
      end
      register_log_source(
        Msf::MCP::LOG_SOURCE,
        Msf::MCP::Logging::Sinks::JsonFlatfile.new(log_file),
        Rex::Logging::LEV_3
      )
    end

    after do
      if log_source_registered?(Msf::MCP::LOG_SOURCE)
        deregister_log_source(Msf::MCP::LOG_SOURCE)
      end
      File.delete(log_file) if File.exist?(log_file)
    end

    context 'when starting RPC server' do
      before do
        allow(File).to receive(:executable?).with(Msf::MCP::RpcManager::MSFRPCD_PATH).and_return(true)
        allow(Process).to receive(:spawn).and_return(12345)
      end

      it 'logs the startup event' do
        manager.start_rpc_server
        expect(File.read(log_file)).to match(/Starting.*RPC/i)
      end
    end

    context 'when stopping RPC server' do
      before do
        manager.instance_variable_set(:@rpc_pid, 12345)
        manager.instance_variable_set(:@rpc_managed, true)
        allow(Process).to receive(:kill)
        allow(Process).to receive(:waitpid).and_return(12345)
      end

      it 'logs the shutdown event' do
        manager.stop_rpc_server
        expect(File.read(log_file)).to match(/Stopping.*RPC/i)
      end
    end

    context 'when RPC availability check succeeds' do
      it 'logs at DEBUG level' do
        tcp_socket = instance_double('Rex::Socket::Tcp')
        allow(Rex::Socket::Tcp).to receive(:create).and_return(tcp_socket)
        allow(tcp_socket).to receive(:close)

        manager.rpc_available?
        expect(File.read(log_file)).to include('RPC server is available')
      end
    end
  end

  describe 'configuration edge cases' do
    context 'when msf_api section is missing auto_start_rpc key' do
      let(:config_without_auto_start) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].reject { |k, _| k == :auto_start_rpc }
        config
      end

      it 'defaults to auto_start_enabled? returning true for localhost messagepack' do
        manager = described_class.new(config: config_without_auto_start, output: output)
        expect(manager.auto_start_enabled?).to be true
      end
    end

    context 'with SSL disabled' do
      let(:no_ssl_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(ssl: false)
        config
      end

      it 'passes SSL setting when spawning msfrpcd' do
        manager = described_class.new(config: no_ssl_config, output: output)
        allow(File).to receive(:executable?).with(Msf::MCP::RpcManager::MSFRPCD_PATH).and_return(true)

        expect(Process).to receive(:spawn) do |_env, _path, *cmd_args|
          expect(cmd_args.flatten).to include('-S')
        end.and_return(11111)

        manager.start_rpc_server
      end
    end

    context 'with custom port' do
      let(:custom_port_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(port: 44444)
        config
      end

      it 'uses the configured port for availability checks' do
        manager = described_class.new(config: custom_port_config, output: output)

        expect(Rex::Socket::Tcp).to receive(:create).with(
          'PeerHost' => 'localhost',
          'PeerPort' => 44444
        ).and_raise(Rex::ConnectionError)
        manager.rpc_available?
      end
    end
  end

  describe '#credentials_provided?' do
    context 'when both user and password are present' do
      it 'returns true' do
        manager = described_class.new(config: default_config, output: output)
        expect(manager.send(:credentials_provided?)).to be true
      end
    end

    context 'when user is nil' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(user: nil)
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:credentials_provided?)).to be false
      end
    end

    context 'when password is nil' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(password: nil)
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:credentials_provided?)).to be false
      end
    end

    context 'when user is empty string' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(user: '')
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:credentials_provided?)).to be false
      end
    end

    context 'when password is empty string' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(password: '')
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:credentials_provided?)).to be false
      end
    end

    context 'when user is whitespace only' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(user: '   ')
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:credentials_provided?)).to be false
      end
    end

    context 'when both are nil' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(user: nil, password: nil)
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:credentials_provided?)).to be false
      end
    end
  end

  describe '#token_provided?' do
    context 'when token is present' do
      it 'returns true' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(token: 'valid_token')
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:token_provided?)).to be true
      end
    end

    context 'when token is nil' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(token: nil)
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:token_provided?)).to be false
      end
    end

    context 'when token is empty string' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(token: '')
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:token_provided?)).to be false
      end
    end

    context 'when token is whitespace only' do
      it 'returns false' do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(token: '   ')
        manager = described_class.new(config: config, output: output)
        expect(manager.send(:token_provided?)).to be false
      end
    end

    context 'when token key is absent' do
      it 'returns false' do
        manager = described_class.new(config: default_config, output: output)
        expect(manager.send(:token_provided?)).to be false
      end
    end
  end

  describe '#generate_random_credentials' do
    let(:config) do
      c = default_config.dup
      c[:msf_api] = c[:msf_api].merge(user: nil, password: nil)
      c
    end
    let(:manager) { described_class.new(config: config, output: output) }

    it 'sets a random hex user in the config' do
      manager.send(:generate_random_credentials)
      expect(config[:msf_api][:user]).to match(/\A[0-9a-f]{16}\z/)
    end

    it 'sets a random hex password in the config' do
      manager.send(:generate_random_credentials)
      expect(config[:msf_api][:password]).to match(/\A[0-9a-f]{32}\z/)
    end

    it 'generates different credentials on each call' do
      manager.send(:generate_random_credentials)
      first_user = config[:msf_api][:user]
      first_password = config[:msf_api][:password]

      manager.send(:generate_random_credentials)
      expect(config[:msf_api][:user]).not_to eq(first_user)
      expect(config[:msf_api][:password]).not_to eq(first_password)
    end

    it 'outputs a message about generated credentials' do
      manager.send(:generate_random_credentials)
      expect(output.string).to include('Generated random credentials')
    end

    it 'logs the event via Rex' do
      log_file = Tempfile.new('creds_log').tap(&:close).path
      if log_source_registered?(Msf::MCP::LOG_SOURCE)
        deregister_log_source(Msf::MCP::LOG_SOURCE)
      end
      register_log_source(
        Msf::MCP::LOG_SOURCE,
        Msf::MCP::Logging::Sinks::JsonFlatfile.new(log_file),
        Rex::Logging::LEV_3
      )

      manager.send(:generate_random_credentials)

      content = File.read(log_file)
      expect(content).to match(/Generated random credentials/i)

      deregister_log_source(Msf::MCP::LOG_SOURCE)
      File.delete(log_file)
    end
  end

  describe 'ensure_rpc_available' do
    let(:manager) { described_class.new(config: default_config, output: output) }

    context 'when RPC is already available' do
      before do
        allow(manager).to receive(:rpc_available?).and_return(true)
      end

      it 'does not start a new RPC server' do
        expect(manager).not_to receive(:start_rpc_server)
        manager.ensure_rpc_available
      end

      it 'outputs that RPC is already running' do
        manager.ensure_rpc_available
        expect(output.string).to include('already running')
      end
    end

    context 'when RPC is already available but no credentials provided' do
      let(:no_creds_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(user: nil, password: nil)
        config
      end
      let(:manager) { described_class.new(config: no_creds_config, output: output) }

      before do
        allow(manager).to receive(:rpc_available?).and_return(true)
      end

      it 'raises RpcStartupError' do
        expect { manager.ensure_rpc_available }.to raise_error(
          Msf::MCP::Metasploit::RpcStartupError, /already running.*no credentials/i
        )
      end
    end

    context 'when RPC is already available but credentials are empty strings' do
      let(:empty_creds_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(user: '', password: '')
        config
      end
      let(:manager) { described_class.new(config: empty_creds_config, output: output) }

      before do
        allow(manager).to receive(:rpc_available?).and_return(true)
      end

      it 'raises RpcStartupError' do
        expect { manager.ensure_rpc_available }.to raise_error(
          Msf::MCP::Metasploit::RpcStartupError, /already running.*no credentials/i
        )
      end
    end

    context 'when RPC is already available with JSON-RPC type and token provided' do
      let(:jsonrpc_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(type: 'json-rpc', token: 'valid_token')
        config
      end
      let(:manager) { described_class.new(config: jsonrpc_config, output: output) }

      before do
        allow(manager).to receive(:rpc_available?).and_return(true)
      end

      it 'does not raise' do
        expect { manager.ensure_rpc_available }.not_to raise_error
      end
    end

    context 'when RPC is already available with JSON-RPC type but no token' do
      let(:jsonrpc_no_token_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(type: 'json-rpc', token: nil)
        config
      end
      let(:manager) { described_class.new(config: jsonrpc_no_token_config, output: output) }

      before do
        allow(manager).to receive(:rpc_available?).and_return(true)
      end

      it 'raises RpcStartupError about missing token' do
        expect { manager.ensure_rpc_available }.to raise_error(
          Msf::MCP::Metasploit::RpcStartupError, /already running.*no token/i
        )
      end
    end

    context 'when RPC is not available with JSON-RPC type' do
      let(:jsonrpc_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(type: 'json-rpc', token: 'valid_token')
        config
      end
      let(:manager) { described_class.new(config: jsonrpc_config, output: output) }

      before do
        allow(manager).to receive(:rpc_available?).and_return(false)
      end

      it 'raises RpcStartupError about auto-start not supported' do
        expect { manager.ensure_rpc_available }.to raise_error(
          Msf::MCP::Metasploit::RpcStartupError, /auto-start is not supported for JSON-RPC/i
        )
      end
    end

    context 'when RPC is not available and auto-start is enabled' do
      before do
        allow(manager).to receive(:rpc_available?).and_return(false, true)
        allow(manager).to receive(:auto_start_enabled?).and_return(true)
        allow(manager).to receive(:start_rpc_server)
        allow(manager).to receive(:wait_for_rpc).and_return(true)
      end

      it 'starts the RPC server' do
        expect(manager).to receive(:start_rpc_server)
        manager.ensure_rpc_available
      end

      it 'waits for the RPC server to become available' do
        expect(manager).to receive(:wait_for_rpc)
        manager.ensure_rpc_available
      end
    end

    context 'when RPC is not available, auto-start enabled, and no credentials' do
      let(:no_creds_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(user: nil, password: nil)
        config
      end
      let(:manager) { described_class.new(config: no_creds_config, output: output) }

      before do
        allow(manager).to receive(:rpc_available?).and_return(false)
        allow(manager).to receive(:auto_start_enabled?).and_return(true)
        allow(manager).to receive(:start_rpc_server)
        allow(manager).to receive(:wait_for_rpc).and_return(true)
      end

      it 'generates random credentials' do
        manager.ensure_rpc_available
        expect(no_creds_config[:msf_api][:user]).not_to be_nil
        expect(no_creds_config[:msf_api][:user]).not_to be_empty
        expect(no_creds_config[:msf_api][:password]).not_to be_nil
        expect(no_creds_config[:msf_api][:password]).not_to be_empty
      end

      it 'outputs a message about generated credentials' do
        manager.ensure_rpc_available
        expect(output.string).to include('Generated random credentials')
      end

      it 'generates a 16-character hex username' do
        manager.ensure_rpc_available
        expect(no_creds_config[:msf_api][:user]).to match(/\A[0-9a-f]{16}\z/)
      end

      it 'generates a 32-character hex password' do
        manager.ensure_rpc_available
        expect(no_creds_config[:msf_api][:password]).to match(/\A[0-9a-f]{32}\z/)
      end

      it 'still starts the RPC server after generating credentials' do
        expect(manager).to receive(:start_rpc_server)
        manager.ensure_rpc_available
      end
    end

    context 'when RPC is not available and auto-start is disabled' do
      let(:disabled_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(auto_start_rpc: false)
        config
      end
      let(:manager) { described_class.new(config: disabled_config, output: output) }

      before do
        allow(manager).to receive(:rpc_available?).and_return(false)
      end

      it 'does not start an RPC server' do
        expect(manager).not_to receive(:start_rpc_server)
        expect { manager.ensure_rpc_available }.to raise_error(Msf::MCP::Metasploit::RpcStartupError)
      end

      it 'raises RpcStartupError about the unavailable RPC server' do
        expect { manager.ensure_rpc_available }.to raise_error(
          Msf::MCP::Metasploit::RpcStartupError, /not running.*auto-start is disabled/i
        )
      end
    end

    context 'when RPC is not available and host is remote' do
      let(:remote_config) do
        config = default_config.dup
        config[:msf_api] = config[:msf_api].merge(host: '192.0.2.1')
        config
      end
      let(:manager) { described_class.new(config: remote_config, output: output) }

      before do
        allow(manager).to receive(:rpc_available?).and_return(false)
      end

      it 'does not attempt to start the RPC server' do
        expect(manager).not_to receive(:start_rpc_server)
        expect { manager.ensure_rpc_available }.to raise_error(Msf::MCP::Metasploit::RpcStartupError)
      end

      it 'raises RpcStartupError about the remote host' do
        expect { manager.ensure_rpc_available }.to raise_error(
          Msf::MCP::Metasploit::RpcStartupError, /not available.*192\.0\.2\.1/
        )
      end
    end
  end
end
