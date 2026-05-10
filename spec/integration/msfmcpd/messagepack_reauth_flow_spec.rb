# frozen_string_literal: true

require 'msf/core/mcp'
require 'webmock/rspec'

RSpec.describe 'MessagePack Re-Authentication Flow Integration' do
  before(:all) do
    WebMock.disable_net_connect!(allow_localhost: false)
  end

  after(:all) do
    WebMock.allow_net_connect!
  end

  let(:host) { 'localhost' }
  let(:port) { 55553 }
  let(:endpoint) { '/api/' }
  let(:api_url) { "https://#{host}:#{port}#{endpoint}" }
  let(:user) { 'test_user' }
  let(:password) { 'test_password' }

  describe 'Automatic Re-Authentication on Token Expiry' do
    it 're-authenticates and retries when API call returns 401' do
      call_count = 0

      # Stub all POST requests and dispatch based on body content
      stub_request(:post, api_url).to_return do |request|
        body = MessagePack.unpack(request.body)
        call_count += 1

        case call_count
        when 1
          # Initial authentication succeeds
          expect(body[0]).to eq('auth.login')
          {
            status: 200,
            body: { 'result' => 'success', 'token' => 'initial_token' }.to_msgpack,
            headers: { 'Content-Type' => 'binary/message-pack' }
          }
        when 2
          # First API call returns 401 (token expired)
          expect(body[0]).to eq('module.search')
          expect(body[1]).to eq('initial_token')
          {
            status: 401,
            body: { 'error_message' => 'Token expired' }.to_msgpack,
            headers: { 'Content-Type' => 'binary/message-pack' }
          }
        when 3
          # Re-authentication succeeds with new token
          expect(body[0]).to eq('auth.login')
          {
            status: 200,
            body: { 'result' => 'success', 'token' => 'refreshed_token' }.to_msgpack,
            headers: { 'Content-Type' => 'binary/message-pack' }
          }
        when 4
          # Retry with new token succeeds
          expect(body[0]).to eq('module.search')
          expect(body[1]).to eq('refreshed_token')
          {
            status: 200,
            body: [{ 'fullname' => 'exploit/test', 'type' => 'exploit', 'name' => 'test' }].to_msgpack,
            headers: { 'Content-Type' => 'binary/message-pack' }
          }
        else
          raise "Unexpected request ##{call_count}: #{body.inspect}"
        end
      end

      client = Msf::MCP::Metasploit::MessagePackClient.new(
        host: host,
        port: port,
        endpoint: endpoint
      )
      client.authenticate(user, password)

      # This call should trigger: 401 → re-auth → retry → success
      result = client.search_modules('smb')

      expect(result).to be_an(Array)
      expect(result.first['fullname']).to eq('exploit/test')
      expect(client.instance_variable_get(:@token)).to eq('refreshed_token')
      expect(call_count).to eq(4)
    end

    it 'gives up after max retries when re-auth succeeds but API keeps failing' do
      call_count = 0

      stub_request(:post, api_url).to_return do |request|
        body = MessagePack.unpack(request.body)
        call_count += 1

        if body[0] == 'auth.login'
          {
            status: 200,
            body: { 'result' => 'success', 'token' => "token_#{call_count}" }.to_msgpack,
            headers: { 'Content-Type' => 'binary/message-pack' }
          }
        else
          # API calls always return 401
          {
            status: 401,
            body: { 'error_message' => 'Token invalid' }.to_msgpack,
            headers: { 'Content-Type' => 'binary/message-pack' }
          }
        end
      end

      client = Msf::MCP::Metasploit::MessagePackClient.new(
        host: host,
        port: port,
        endpoint: endpoint
      )
      client.authenticate(user, password)

      # Should exhaust retries (max_retries=2) and re-raise
      expect {
        client.search_modules('smb')
      }.to raise_error(Msf::MCP::Metasploit::AuthenticationError)
    end

    it 'propagates re-auth failure through the tool layer as an error response' do
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # All subsequent requests return 401
      stub_request(:post, api_url)
        .with { |req| MessagePack.unpack(req.body)[0] != 'auth.login' }
        .to_return(
          status: 401,
          body: { 'error_message' => 'Token invalid' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      client = Msf::MCP::Metasploit::MessagePackClient.new(
        host: host,
        port: port,
        endpoint: endpoint
      )
      client.authenticate(user, password)

      limiter = Msf::MCP::Security::RateLimiter.new(requests_per_minute: 60)
      server_context = { msf_client: client, rate_limiter: limiter }

      result = Msf::MCP::Tools::SearchModules.call(query: 'smb', server_context: server_context)

      expect(result.error?).to be true
      expect(result.content.first[:text]).to include('Authentication failed')
    end
  end
end
