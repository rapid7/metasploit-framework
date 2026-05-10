# frozen_string_literal: true

require 'msf/core/mcp'
require 'webmock/rspec'

RSpec.describe 'JSON-RPC Authentication Flow Integration' do
  # Disable real HTTP connections for integration tests
  before(:all) do
    WebMock.disable_net_connect!(allow_localhost: false)
  end

  after(:all) do
    WebMock.allow_net_connect!
  end

  let(:host) { 'localhost' }
  let(:port) { 8081 }
  let(:endpoint) { '/api/v1/json-rpc' }
  let(:token) { 'test_bearer_token_12345' }
  let(:jsonrpc_url) { "https://#{host}:#{port}#{endpoint}" }

  describe 'Bearer Token Authentication' do
    it 'uses bearer token in HTTP headers' do
      # Stub HTTP endpoint and verify Authorization header
      stub = stub_request(:post, jsonrpc_url)
        .with(
          headers: {
            'Authorization' => "Bearer #{token}",
            'Content-Type' => 'application/json'
          }
        )
        .to_return(
          status: 200,
          body: { jsonrpc: '2.0', result: { modules: [] }, id: 1 }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client = Msf::MCP::Metasploit::JsonRpcClient.new(
        host: host,
        port: port,
        endpoint: endpoint,
        token: token
      )

      client.call_api('module.search', ['smb'])

      # Verify the HTTP request was made with correct Authorization header
      expect(stub).to have_been_requested.once
    end

    it 'follows stateless request pattern (no session management)' do
      client = Msf::MCP::Metasploit::JsonRpcClient.new(
        host: host,
        port: port,
        endpoint: endpoint,
        token: token
      )

      # No session storage should exist (only token)
      expect(client.instance_variable_defined?(:@session_id)).to eq(false)
      expect(client.instance_variable_defined?(:@session_token)).to eq(false)

      # Has token stored
      expect(client.instance_variable_get(:@token)).to eq(token)

      # No session state (only token which is stateless)
      expect(client.instance_variables.grep(/@session/)).to be_empty
    end
  end
end
