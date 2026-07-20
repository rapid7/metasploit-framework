# frozen_string_literal: true

require 'msf/core/mcp'
require 'webmock/rspec'

RSpec.describe 'Rate Limiting Integration' do
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
  let(:api_url) { "https://#{host}:#{port}#{endpoint}" }
  let(:user) { 'test_user' }
  let(:password) { 'test_password' }

  describe 'Rate Limiting Across Multiple Tool HTTP Requests' do
    it 'enforces rate limit across multiple tool calls with HTTP requests' do
      # Stub authentication endpoint
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub module search endpoint
      search_stub = stub_request(:post, api_url)
        .with(body: ['module.search', 'test_token', 'smb'].to_msgpack)
        .to_return(
          status: 200,
          body: [{ 'fullname' => 'auxiliary/scanner/smb/smb_version' }].to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Create rate limiter with low limit
      limiter = Msf::MCP::Security::RateLimiter.new(requests_per_minute: 3, burst_size: 3)

      # Create authenticated client
      client = Msf::MCP::Metasploit::MessagePackClient.new(
        host: host,
        port: port,
        endpoint: endpoint
      )
      client.authenticate(user, password)

      # Create server context
      server_context = {
        msf_client: client,
        rate_limiter: limiter
      }

      # First 3 tool calls should succeed (within rate limit)
      3.times do
        expect {
          Msf::MCP::Tools::SearchModules.call(
            query: 'smb',
            limit: 10,
            server_context: server_context
          )
        }.not_to raise_error
      end

      # Verify exactly 3 HTTP requests were made (plus 1 for auth)
      expect(search_stub).to have_been_requested.times(3)

      # 4th call should be rate limited before making HTTP request
      result = Msf::MCP::Tools::SearchModules.call(query: 'smb', limit: 10, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Rate limit exceeded/)

      # Verify still only 3 search requests (4th was blocked by rate limiter)
      expect(search_stub).to have_been_requested.times(3)
    end

    it 'applies global rate limit across different tools with HTTP calls' do
      # Stub authentication
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub search modules
      search_stub = stub_request(:post, api_url)
        .with(body: ['module.search', 'test_token', 'smb'].to_msgpack)
        .to_return(
          status: 200,
          body: [].to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub db.hosts
      hosts_stub = stub_request(:post, api_url)
        .with(body: ['db.hosts', 'test_token', { workspace: 'default' }].to_msgpack)
        .to_return(
          status: 200,
          body: { 'hosts' => [] }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      limiter = Msf::MCP::Security::RateLimiter.new(requests_per_minute: 5, burst_size: 5)
      client = Msf::MCP::Metasploit::MessagePackClient.new(
        host: host,
        port: port,
        endpoint: endpoint
      )
      client.authenticate(user, password)

      server_context = {
        msf_client: client,
        rate_limiter: limiter
      }

      # Make 3 search_modules calls
      3.times do
        Msf::MCP::Tools::SearchModules.call(
          query: 'smb',
          limit: 10,
          server_context: server_context
        )
      end

      # Make 2 host_info calls
      2.times do
        Msf::MCP::Tools::HostInfo.call(
          workspace: 'default',
          server_context: server_context
        )
      end

      # 6th call (different tool) should be rate limited
      result = Msf::MCP::Tools::SearchModules.call(query: 'http', limit: 10, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Rate limit exceeded/)

      # Verify HTTP request counts
      expect(search_stub).to have_been_requested.times(3)
      expect(hosts_stub).to have_been_requested.times(2)
    end
  end
end
