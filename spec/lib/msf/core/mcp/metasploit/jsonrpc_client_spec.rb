# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Metasploit::JsonRpcClient do
  let(:host) { 'localhost' }
  let(:port) { 8081 }
  let(:endpoint) { '/api/v1/json-rpc' }
  let(:token) { 'test_token_123' }
  let(:ssl) { false }
  let(:client) { described_class.new(host: host, port: port, endpoint: endpoint, token: token, ssl: ssl) }

  describe '#initialize' do
    it 'sets instance variables' do
      expect(client.instance_variable_get(:@host)).to eq(host)
      expect(client.instance_variable_get(:@port)).to eq(port)
      expect(client.instance_variable_get(:@endpoint)).to eq(endpoint)
      expect(client.instance_variable_get(:@token)).to eq(token)
      expect(client.instance_variable_get(:@ssl)).to eq(ssl)
      expect(client.instance_variable_get(:@request_id)).to eq(0)
    end

    it 'defaults ssl to true when not specified' do
      client_with_defaults = described_class.new(host: host, port: port, token: token)
      expect(client_with_defaults.instance_variable_get(:@ssl)).to eq(true)
    end
  end

  describe '#authenticate' do
    it 'is a no-op that returns the existing token' do
      result = client.authenticate('user', 'pass')
      expect(result).to eq(token)
    end

    it 'does not change the token' do
      client.authenticate('user', 'pass')
      expect(client.instance_variable_get(:@token)).to eq(token)
    end
  end

  describe 'SSL configuration' do
    let(:http_mock) { instance_double(Net::HTTP) }

    before do
      allow(Net::HTTP).to receive(:new).and_return(http_mock)
      allow(http_mock).to receive(:use_ssl=)
      allow(http_mock).to receive(:verify_mode=)
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: '{"result": {}}')
      )
    end

    context 'when ssl is true' do
      let(:ssl) { true }

      it 'enables SSL on Net::HTTP client' do
        expect(http_mock).to receive(:use_ssl=).with(true)
        client.send(:send_request, { jsonrpc: '2.0', method: 'test', id: 1 })
      end

      it 'sets verify_mode to VERIFY_NONE' do
        expect(http_mock).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
        client.send(:send_request, { jsonrpc: '2.0', method: 'test', id: 1 })
      end
    end

    context 'when ssl is false' do
      let(:ssl) { false }

      it 'disables SSL on Net::HTTP client' do
        expect(http_mock).to receive(:use_ssl=).with(false)
        client.send(:send_request, { jsonrpc: '2.0', method: 'test', id: 1 })
      end

      it 'does not set verify_mode' do
        expect(http_mock).not_to receive(:verify_mode=)
        client.send(:send_request, { jsonrpc: '2.0', method: 'test', id: 1 })
      end
    end

    context 'when ssl is explicitly set to true in constructor' do
      let(:client) { described_class.new(host: host, port: port, token: token, ssl: true) }

      it 'configures HTTPS connection' do
        expect(http_mock).to receive(:use_ssl=).with(true)
        expect(http_mock).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
        client.send(:send_request, { jsonrpc: '2.0', method: 'test', id: 1 })
      end
    end

    context 'with default SSL setting' do
      let(:client) { described_class.new(host: host, port: port, token: token) }

      it 'uses SSL by default' do
        expect(http_mock).to receive(:use_ssl=).with(true)
        expect(http_mock).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
        client.send(:send_request, { jsonrpc: '2.0', method: 'test', id: 1 })
      end
    end
  end

  describe '#call_api' do
    before do
      allow(client).to receive(:send_request).and_return({ 'result' => { 'modules' => [] } })
    end

    it 'increments request_id' do
      expect { client.call_api('module.search', ['smb']) }.to change { client.instance_variable_get(:@request_id) }.by(1)
    end

    it 'sends JSON-RPC 2.0 request with correct structure' do
      expect(client).to receive(:send_request) do |body|
        expect(body[:jsonrpc]).to eq('2.0')
        expect(body[:method]).to eq('module.search')
        expect(body[:params]).to eq(['smb'])
        expect(body[:id]).to eq(1)
        { 'result' => {} }
      end

      client.call_api('module.search', ['smb'])
    end

    it 'returns result from response' do
      result = client.call_api('module.search', ['smb'])
      expect(result).to eq({ 'modules' => [] })
    end

    it 'raises ArgumentError when args is not an Array' do
      expect {
        client.call_api('module.search', 'smb')
      }.to raise_error(ArgumentError, /args must be an Array/)
    end

    it 'raises ArgumentError when args is a Hash' do
      expect {
        client.call_api('module.search', { query: 'smb' })
      }.to raise_error(ArgumentError, /args must be an Array/)
    end

    it 'raises APIError when response contains error' do
      allow(client).to receive(:send_request).and_return({ 'error' => { 'message' => 'Invalid method' } })

      expect {
        client.call_api('invalid.method')
      }.to raise_error(Msf::MCP::Metasploit::APIError, 'Invalid method')
    end

    it 'raises APIError with default message when error has no message' do
      allow(client).to receive(:send_request).and_return({ 'error' => {} })

      expect {
        client.call_api('invalid.method')
      }.to raise_error(Msf::MCP::Metasploit::APIError, 'Unknown error')
    end
  end

  describe '#shutdown' do
    it 'finishes HTTP connection if started' do
      http_mock = double('Net::HTTP')
      allow(http_mock).to receive(:started?).and_return(true)
      allow(http_mock).to receive(:finish)

      client.instance_variable_set(:@http, http_mock)
      client.shutdown

      expect(http_mock).to have_received(:finish)
    end

    it 'does nothing if HTTP connection not started' do
      http_mock = double('Net::HTTP')
      allow(http_mock).to receive(:started?).and_return(false)

      client.instance_variable_set(:@http, http_mock)
      expect { client.shutdown }.not_to raise_error
    end

    it 'handles nil HTTP connection' do
      client.instance_variable_set(:@http, nil)
      expect { client.shutdown }.not_to raise_error
    end
  end

  describe 'debug logging' do
    let(:http_mock) { instance_double(Net::HTTP) }

    before do
      allow(Net::HTTP).to receive(:new).and_return(http_mock)
      allow(http_mock).to receive(:use_ssl=)
      allow(http_mock).to receive(:verify_mode=)
    end

    it 'does not raise when no Rex sink is registered' do
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: '{"result": {}}')
      )
      expect { client.call_api('module.search', ['smb']) }.not_to raise_error
    end

    it 'calls dlog for request and response' do
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: '{"result": {}}')
      )

      expect(client).to receive(:dlog).with(hash_including(message: 'JSON-RPC request'), anything, anything).ordered
      expect(client).to receive(:dlog).with(hash_including(message: 'JSON-RPC response'), anything, anything).ordered

      client.call_api('module.search', ['smb'])
    end
  end

  describe 'API wrapper methods' do
    describe '#search_modules' do
      it 'calls call_api with correct method and params' do
        expect(client).to receive(:call_api).with('module.search', ['smb'])
        client.search_modules('smb')
      end

      it 'returns search results' do
        allow(client).to receive(:call_api).and_return({ 'modules' => [{ 'name' => 'auxiliary/scanner/smb/smb_version' }] })
        result = client.search_modules('smb')
        expect(result['modules']).to be_an(Array)
      end
    end

    describe '#module_info' do
      it 'calls call_api with correct method and params' do
        expect(client).to receive(:call_api).with('module.info', ['exploit', 'windows/smb/ms17_010_eternalblue'])
        client.module_info('exploit', 'windows/smb/ms17_010_eternalblue')
      end

      it 'returns module information' do
        module_data = { 'name' => 'MS17-010 EternalBlue', 'rank' => 'good' }
        allow(client).to receive(:call_api).and_return(module_data)
        result = client.module_info('exploit', 'windows/smb/ms17_010_eternalblue')
        expect(result).to eq(module_data)
      end
    end

    describe '#db_hosts' do
      it 'calls call_api with correct method' do
        expect(client).to receive(:call_api).with('db.hosts', [{}])
        client.db_hosts
      end

      it 'calls call_api with options' do
        expect(client).to receive(:call_api).with('db.hosts', [{workspace: 'default', limit: 10}])
        client.db_hosts(workspace: 'default', limit: 10)
      end

      it 'returns hosts array' do
        hosts_data = { 'hosts' => [{ 'address' => '192.168.1.1' }] }
        allow(client).to receive(:call_api).and_return(hosts_data)
        result = client.db_hosts
        expect(result['hosts']).to be_an(Array)
      end
    end

    describe '#db_services' do
      it 'calls call_api with correct method' do
        expect(client).to receive(:call_api).with('db.services', [{}])
        client.db_services
      end

      it 'passes options to call_api' do
        expect(client).to receive(:call_api).with('db.services', [{workspace: 'default'}])
        client.db_services(workspace: 'default')
      end
    end

    describe '#db_vulns' do
      it 'calls call_api with correct method' do
        expect(client).to receive(:call_api).with('db.vulns', [{}])
        client.db_vulns
      end

      it 'passes options to call_api' do
        expect(client).to receive(:call_api).with('db.vulns', [{workspace: 'default'}])
        client.db_vulns(workspace: 'default')
      end
    end

    describe '#db_notes' do
      it 'calls call_api with correct method' do
        expect(client).to receive(:call_api).with('db.notes', [{}])
        client.db_notes
      end

      it 'passes options to call_api' do
        expect(client).to receive(:call_api).with('db.notes', [{workspace: 'default'}])
        client.db_notes(workspace: 'default')
      end
    end

    describe '#db_creds' do
      it 'calls call_api with correct method' do
        expect(client).to receive(:call_api).with('db.creds', [{}])
        client.db_creds
      end

      it 'passes options to call_api' do
        expect(client).to receive(:call_api).with('db.creds', [{workspace: 'default'}])
        client.db_creds(workspace: 'default')
      end
    end

    describe '#db_loot' do
      it 'calls call_api with correct method' do
        expect(client).to receive(:call_api).with('db.loots', [{}])
        client.db_loot
      end

      it 'passes options to call_api' do
        expect(client).to receive(:call_api).with('db.loots', [{workspace: 'default'}])
        client.db_loot(workspace: 'default')
      end
    end
  end
end
