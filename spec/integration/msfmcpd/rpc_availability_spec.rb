# frozen_string_literal: true

require 'msf/core/mcp'
require 'stringio'
require 'tempfile'

RSpec.describe 'RPC Availability Integration' do
  let(:output) { StringIO.new }
  let(:file_fixtures_path) { File.join(Msf::Config.install_root, 'spec', 'file_fixtures') }
  let(:valid_messagepack_path) { File.join(file_fixtures_path, 'config_files', 'msfmcpd', 'valid_messagepack.yaml') }

  describe 'Application run with RPC already available but no credentials' do
    it 'exits with RPC startup error when MessagePack credentials are missing' do
      # Config with no credentials — validator allows this because auto-start
      # could generate them, but RPC is already running so generation won't happen
      config = {
        msf_api: {
          type: 'messagepack',
          host: 'localhost',
          port: 55553,
          auto_start_rpc: true
        }
      }

      config_file = Tempfile.new(['no_creds', '.yaml'])
      config_file.write(YAML.dump(JSON.parse(config.to_json)))
      config_file.flush

      app = Msf::MCP::Application.new(['--config', config_file.path], output: output)

      # Stub RPC as already available
      allow_any_instance_of(Msf::MCP::RpcManager).to receive(:rpc_available?).and_return(true)
      allow(Signal).to receive(:trap)

      expect { app.run }.to raise_error(SystemExit) do |e|
        expect(e.status).to eq(1)
      end

      expect(output.string).to include('RPC startup error')
      expect(output.string).to include('no credentials')

      config_file.close
      config_file.unlink
    end

    it 'exits with RPC startup error when JSON-RPC token is missing' do
      config = {
        msf_api: {
          type: 'json-rpc',
          host: 'localhost',
          port: 8081
        }
      }

      config_file = Tempfile.new(['no_token', '.yaml'])
      config_file.write(YAML.dump(JSON.parse(config.to_json)))
      config_file.flush

      app = Msf::MCP::Application.new(['--config', config_file.path], output: output)

      # Stub RPC as already available
      allow_any_instance_of(Msf::MCP::RpcManager).to receive(:rpc_available?).and_return(true)
      allow(Signal).to receive(:trap)

      expect { app.run }.to raise_error(SystemExit) do |e|
        expect(e.status).to eq(1)
      end

      # The validator catches missing token before RpcManager runs
      expect(output.string).to match(/token|Configuration validation failed/i)

      config_file.close
      config_file.unlink
    end

    it 'proceeds when RPC is available and credentials are provided' do
      app = Msf::MCP::Application.new(['--config', valid_messagepack_path], output: output)

      # Stub RPC as already available
      allow_any_instance_of(Msf::MCP::RpcManager).to receive(:rpc_available?).and_return(true)

      # Stub the rest of the startup sequence
      mock_client = instance_double(Msf::MCP::Metasploit::Client)
      allow(Msf::MCP::Metasploit::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:authenticate)
      mock_server = instance_double(Msf::MCP::Server)
      allow(Msf::MCP::Server).to receive(:new).and_return(mock_server)
      allow(mock_server).to receive(:start)
      allow(Signal).to receive(:trap)

      expect { app.run }.not_to raise_error

      expect(output.string).to include('already running')
      expect(output.string).to include('Authentication successful')
    end
  end

  describe 'Application run with RPC not available' do
    it 'exits with RPC startup error when auto-start is disabled' do
      config = {
        msf_api: {
          type: 'messagepack',
          host: 'localhost',
          port: 55553,
          user: 'msf',
          password: 'pass',
          auto_start_rpc: false
        }
      }

      config_file = Tempfile.new(['no_autostart', '.yaml'])
      config_file.write(YAML.dump(JSON.parse(config.to_json)))
      config_file.flush

      app = Msf::MCP::Application.new(['--config', config_file.path], output: output)

      # Stub RPC as not available
      allow_any_instance_of(Msf::MCP::RpcManager).to receive(:rpc_available?).and_return(false)
      allow(Signal).to receive(:trap)

      expect { app.run }.to raise_error(SystemExit) do |e|
        expect(e.status).to eq(1)
      end

      expect(output.string).to include('RPC startup error')
      expect(output.string).to include('auto-start is disabled')

      config_file.close
      config_file.unlink
    end

    it 'exits with RPC startup error on remote host' do
      config = {
        msf_api: {
          type: 'messagepack',
          host: '192.0.2.1',
          port: 55553,
          user: 'msf',
          password: 'pass',
          auto_start_rpc: true
        }
      }

      config_file = Tempfile.new(['remote_host', '.yaml'])
      config_file.write(YAML.dump(JSON.parse(config.to_json)))
      config_file.flush

      app = Msf::MCP::Application.new(['--config', config_file.path], output: output)

      # Stub RPC as not available
      allow_any_instance_of(Msf::MCP::RpcManager).to receive(:rpc_available?).and_return(false)
      allow(Signal).to receive(:trap)

      expect { app.run }.to raise_error(SystemExit) do |e|
        expect(e.status).to eq(1)
      end

      expect(output.string).to include('RPC startup error')
      expect(output.string).to include('192.0.2.1')

      config_file.close
      config_file.unlink
    end
  end
end
