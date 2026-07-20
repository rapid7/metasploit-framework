# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Metasploit::Client do
  let(:jsonrpc_client) { double('Msf::MCP::Metasploit::JsonRpcClient') }
  let(:messagepack_client) { double('Msf::MCP::Metasploit::MessagePackClient') }

  describe '#initialize with JSON-RPC' do
    it 'creates JsonRpcClient for json-rpc api_type' do
      expect(Msf::MCP::Metasploit::JsonRpcClient).to receive(:new).with(
        host: 'localhost',
        port: 8081,
        ssl: true,
        endpoint: '/api/v1/json-rpc',
        token: 'test_token'
      ).and_return(jsonrpc_client)

      client = described_class.new(
        api_type: 'json-rpc',
        host: 'localhost',
        port: 8081,
        ssl: true,
        endpoint: '/api/v1/json-rpc',
        token: 'test_token'
      )

      expect(client.instance_variable_get(:@client)).to eq(jsonrpc_client)
    end
  end

  describe '#initialize with MessagePack' do
    it 'creates MessagePackClient for messagepack api_type' do
      expect(Msf::MCP::Metasploit::MessagePackClient).to receive(:new).with(
        host: 'localhost',
        port: 55553,
        ssl: true,
        endpoint: '/api/'
      ).and_return(messagepack_client)

      client = described_class.new(
        api_type: 'messagepack',
        host: 'localhost',
        port: 55553,
        ssl: true
      )

      expect(client.instance_variable_get(:@client)).to eq(messagepack_client)
    end
  end

  describe '#initialize with invalid API type' do
    it 'raises Error for unknown api_type' do
      expect {
        described_class.new(api_type: 'invalid', host: 'localhost', port: 8081)
      }.to raise_error(Msf::MCP::Error, /Invalid API type/)
    end
  end

  describe '#create_client' do
    it 'uses default MessagePack endpoint when none provided' do
      expect(Msf::MCP::Metasploit::MessagePackClient).to receive(:new).with(
        host: 'localhost',
        port: 55553,
        endpoint: Msf::MCP::Metasploit::MessagePackClient::DEFAULT_ENDPOINT,
        ssl: true
      )

      described_class.new(api_type: 'messagepack', host: 'localhost', port: 55553)
    end

    it 'uses default JSON-RPC endpoint when none provided' do
      expect(Msf::MCP::Metasploit::JsonRpcClient).to receive(:new).with(
        host: 'localhost',
        port: 8081,
        endpoint: Msf::MCP::Metasploit::JsonRpcClient::DEFAULT_ENDPOINT,
        ssl: true,
        token: 'tok'
      )

      described_class.new(api_type: 'json-rpc', host: 'localhost', port: 8081, token: 'tok')
    end

    it 'uses custom endpoint when provided for MessagePack' do
      expect(Msf::MCP::Metasploit::MessagePackClient).to receive(:new).with(
        host: 'localhost',
        port: 55553,
        endpoint: '/custom/api/',
        ssl: false
      )

      described_class.new(api_type: 'messagepack', host: 'localhost', port: 55553, endpoint: '/custom/api/', ssl: false)
    end

    it 'uses custom endpoint when provided for JSON-RPC' do
      expect(Msf::MCP::Metasploit::JsonRpcClient).to receive(:new).with(
        host: 'remote',
        port: 9090,
        endpoint: '/custom/jsonrpc',
        ssl: false,
        token: 'my_token'
      )

      described_class.new(api_type: 'json-rpc', host: 'remote', port: 9090, endpoint: '/custom/jsonrpc', ssl: false, token: 'my_token')
    end

    it 'defaults ssl to true' do
      expect(Msf::MCP::Metasploit::MessagePackClient).to receive(:new).with(
        hash_including(ssl: true)
      )

      described_class.new(api_type: 'messagepack', host: 'localhost', port: 55553)
    end

    it 'includes the invalid api_type in the error message' do
      expect {
        described_class.new(api_type: 'grpc', host: 'localhost', port: 8081)
      }.to raise_error(Msf::MCP::Error, 'Invalid API type: grpc')
    end
  end

  describe 'method delegation' do
    let(:client) do
      allow(Msf::MCP::Metasploit::JsonRpcClient).to receive(:new).and_return(jsonrpc_client)
      described_class.new(api_type: 'json-rpc', host: 'localhost', port: 8081, token: 'test')
    end

    it 'delegates search_modules to underlying client' do
      allow(jsonrpc_client).to receive(:search_modules).with('smb').and_return(['module1'])
      expect(client.search_modules('smb')).to eq(['module1'])
    end

    it 'delegates authenticate to underlying client' do
      allow(jsonrpc_client).to receive(:authenticate).with('user', 'pass').and_return('test')
      expect(client.authenticate('user', 'pass')).to eq('test')
    end

    it 'delegates module_info to underlying client' do
      allow(jsonrpc_client).to receive(:module_info).with('exploit', 'test').and_return({ 'name' => 'test' })
      expect(client.module_info('exploit', 'test')).to eq({ 'name' => 'test' })
    end

    it 'delegates db_hosts to underlying client' do
      allow(jsonrpc_client).to receive(:db_hosts).with({ workspace: 'default' }).and_return({ 'hosts' => [] })
      expect(client.db_hosts({ workspace: 'default' })).to eq({ 'hosts' => [] })
    end

    it 'delegates db_services to underlying client' do
      allow(jsonrpc_client).to receive(:db_services).with({ workspace: 'default' }).and_return({ 'services' => [] })
      expect(client.db_services({ workspace: 'default' })).to eq({ 'services' => [] })
    end

    it 'delegates db_vulns to underlying client' do
      allow(jsonrpc_client).to receive(:db_vulns).with({ workspace: 'default' }).and_return({ 'vulns' => [] })
      expect(client.db_vulns({ workspace: 'default' })).to eq({ 'vulns' => [] })
    end

    it 'delegates db_creds to underlying client' do
      allow(jsonrpc_client).to receive(:db_creds).with({ workspace: 'default' }).and_return({ 'creds' => [] })
      expect(client.db_creds({ workspace: 'default' })).to eq({ 'creds' => [] })
    end

    it 'delegates db_loot to underlying client' do
      allow(jsonrpc_client).to receive(:db_loot).with({ workspace: 'default' }).and_return({ 'loots' => [] })
      expect(client.db_loot({ workspace: 'default' })).to eq({ 'loots' => [] })
    end

    it 'delegates db_notes to underlying client' do
      allow(jsonrpc_client).to receive(:db_notes).with({ workspace: 'default' }).and_return({ 'notes' => [] })
      expect(client.db_notes({ workspace: 'default' })).to eq({ 'notes' => [] })
    end

    it 'delegates shutdown to underlying client' do
      allow(jsonrpc_client).to receive(:shutdown)
      client.shutdown
      expect(jsonrpc_client).to have_received(:shutdown)
    end
  end
end
