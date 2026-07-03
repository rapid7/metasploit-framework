# frozen_string_literal: true

require 'msf/core/mcp'
require 'webmock/rspec'

RSpec.describe 'MessagePack Authentication Flow Integration' do
  # Disable real HTTP connections for integration tests
  before(:all) do
    WebMock.disable_net_connect!(allow_localhost: false)
  end

  after(:all) do
    WebMock.allow_net_connect!
  end

  let(:host) { 'localhost' }
  let(:port) { 55553 }
  let(:endpoint) { '/api/' }
  let(:user) { 'test_user' }
  let(:password) { 'test_password' }
  let(:api_url) { "https://#{host}:#{port}#{endpoint}" }

  describe 'Successful Authentication' do
    it 'authenticates with username and password' do
      # Stub authentication endpoint
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token_12345' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      client = Msf::MCP::Metasploit::MessagePackClient.new(
        host: host,
        port: port,
        endpoint: endpoint
      )

      token = client.authenticate(user, password)
      expect(token).to eq('test_token_12345')
    end
  end

  describe 'Token Reuse' do
    it 'stores token for subsequent API calls' do
      # Stub authentication endpoint
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token_12345' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub subsequent API call with token
      stub_request(:post, api_url)
        .with(body: ['module.search', 'test_token_12345', 'smb'].to_msgpack)
        .to_return(
          status: 200,
          body: [].to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      client = Msf::MCP::Metasploit::MessagePackClient.new(
        host: host,
        port: port,
        endpoint: endpoint
      )

      stored_token = client.authenticate(user, password)

      # Subsequent request should use the stored token
      client.call_api('module.search', ['smb'])

      # Token should still be the same
      expect(client.instance_variable_get(:@token)).to eq(stored_token)
      expect(stored_token).to eq('test_token_12345')
    end
  end
end
