# frozen_string_literal: true

require 'msf/core/mcp'
require 'webmock/rspec'

RSpec.describe 'Tool Execution End-to-End - Database Queries' do
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

  describe 'Database Query Integration with HTTP' do
    it 'executes host query through complete HTTP request flow' do
      # Stub authentication endpoint
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub db.hosts endpoint with realistic response
      hosts_stub = stub_request(:post, api_url)
        .with(body: ['db.hosts', 'test_token', { workspace: 'default' }].to_msgpack)
        .to_return(
          status: 200,
          body: {
            'hosts' => [
              {
                'address' => '192.168.1.100',
                'mac' => '00:11:22:33:44:55',
                'name' => 'server01',
                'os_name' => 'Linux',
                'os_flavor' => 'Ubuntu',
                'state' => 'alive',
                'created_at' => 1609459200,
                'updated_at' => 1640995200
              },
              {
                'address' => '192.168.1.101',
                'mac' => '00:11:22:33:44:56',
                'name' => 'server02',
                'os_name' => 'Windows',
                'os_flavor' => 'Server 2019',
                'state' => 'alive',
                'created_at' => 1609459300,
                'updated_at' => 1640995300
              }
            ]
          }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Create rate limiter
      limiter = Msf::MCP::Security::RateLimiter.new(requests_per_minute: 60, burst_size: 10)

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

      # Execute host query through complete stack
      result = Msf::MCP::Tools::HostInfo.call(
        workspace: 'default',
        server_context: server_context
      )

      # Verify HTTP request was made
      expect(hosts_stub).to have_been_requested.once

      # Verify MCP response structure
      expect(result).to be_a(MCP::Tool::Response)
      expect(result.content).to be_an(Array)
      expect(result.content.first[:type]).to eq('text')

      # Verify data transformation occurred correctly
      data = result.structured_content[:data]
      expect(data).to be_an(Array)
      expect(data.length).to eq(2)
      expect(data.first[:address]).to eq('192.168.1.100')
      expect(data.first[:hostname]).to eq('server01')
      expect(data.first[:os_name]).to eq('Linux')

      # Verify timestamps transformed to ISO 8601
      expect(data.first[:created_at]).to eq('2021-01-01T00:00:00Z')
      expect(data.first[:updated_at]).to eq('2022-01-01T00:00:00Z')

      # Verify metadata
      metadata = result.structured_content[:metadata]
      expect(metadata[:workspace]).to eq('default')
      expect(metadata[:total_items]).to eq(2)
      expect(metadata[:returned_items]).to eq(2)
    end

    it 'applies filters correctly through HTTP request' do
      # Stub authentication
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub db.hosts with filters
      hosts_stub = stub_request(:post, api_url)
        .with(body: ['db.hosts', 'test_token', { workspace: 'default', addresses: '192.168.1.0/24', only_up: true }].to_msgpack)
        .to_return(
          status: 200,
          body: {
            'hosts' => [
              {
                'address' => '192.168.1.100',
                'mac' => '00:11:22:33:44:55',
                'name' => 'filtered_host',
                'state' => 'alive',
                'created_at' => 1609459200
              }
            ]
          }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      limiter = Msf::MCP::Security::RateLimiter.new(requests_per_minute: 60, burst_size: 10)
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

      # Execute query with filters
      result = Msf::MCP::Tools::HostInfo.call(
        workspace: 'default',
        addresses: '192.168.1.0/24',
        only_up: true,
        server_context: server_context
      )

      # Verify HTTP request with filters was made
      expect(hosts_stub).to have_been_requested.once

      # Verify filtered results
      expect(result).to be_a(MCP::Tool::Response)
      data = result.structured_content[:data]
      expect(data.length).to eq(1)
      expect(data.first[:address]).to eq('192.168.1.100')
    end

    it 'executes service query with multiple filters through HTTP' do
      # Stub authentication
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub db.services with filters
      # Note: MessagePack hash key order may vary, so we match any request to db.services
      services_stub = stub_request(:post, api_url)
        .with { |request|
          body = MessagePack.unpack(request.body)
          body[0] == 'db.services' && body[1] == 'test_token' &&
            body[2].is_a?(Hash) && body[2]['workspace'] == 'default'
        }
        .to_return(
          status: 200,
          body: {
            'services' => [
              {
                'host' => '192.168.1.100',
                'port' => 445,
                'proto' => 'tcp',
                'name' => 'microsoft-ds',
                'state' => 'open',
                'created_at' => 1609459200,
                'updated_at' => 1640995200
              }
            ]
          }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      limiter = Msf::MCP::Security::RateLimiter.new(requests_per_minute: 60, burst_size: 10)
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

      # Execute service query with multiple filters
      result = Msf::MCP::Tools::ServiceInfo.call(
        workspace: 'default',
        host: '192.168.1.100',
        ports: '445',
        protocol: 'tcp',
        server_context: server_context
      )

      # Verify HTTP request with all filters was made
      expect(services_stub).to have_been_requested.once

      # Verify results
      expect(result).to be_a(MCP::Tool::Response)
      data = result.structured_content[:data]
      expect(data.length).to eq(1)
      expect(data.first[:host_address]).to eq('192.168.1.100')
      expect(data.first[:port]).to eq(445)
      expect(data.first[:protocol]).to eq('tcp')
      expect(data.first[:name]).to eq('microsoft-ds')
    end

    it 'handles pagination correctly across HTTP boundary' do
      # Stub authentication
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub db.hosts with multiple results
      hosts_stub = stub_request(:post, api_url)
        .with(body: ['db.hosts', 'test_token', { workspace: 'default' }].to_msgpack)
        .to_return(
          status: 200,
          body: {
            'hosts' => [
              { 'address' => '192.168.1.1', 'name' => 'host1', 'state' => 'alive', 'created_at' => 1609459200 },
              { 'address' => '192.168.1.2', 'name' => 'host2', 'state' => 'alive', 'created_at' => 1609459300 },
              { 'address' => '192.168.1.3', 'name' => 'host3', 'state' => 'alive', 'created_at' => 1609459400 },
              { 'address' => '192.168.1.4', 'name' => 'host4', 'state' => 'alive', 'created_at' => 1609459500 },
              { 'address' => '192.168.1.5', 'name' => 'host5', 'state' => 'alive', 'created_at' => 1609459600 }
            ]
          }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      limiter = Msf::MCP::Security::RateLimiter.new(requests_per_minute: 60, burst_size: 10)
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

      # Execute query with pagination (offset=1, limit=2 means items 2 and 3)
      result = Msf::MCP::Tools::HostInfo.call(
        workspace: 'default',
        limit: 2,
        offset: 1,
        server_context: server_context
      )

      # Verify HTTP request was made
      expect(hosts_stub).to have_been_requested.once

      # Verify pagination applied correctly
      expect(result).to be_a(MCP::Tool::Response)
      data = result.structured_content[:data]
      expect(data.length).to eq(2)
      expect(data.first[:address]).to eq('192.168.1.2')
      expect(data.last[:address]).to eq('192.168.1.3')

      # Verify pagination metadata
      metadata = result.structured_content[:metadata]
      expect(metadata[:limit]).to eq(2)
      expect(metadata[:offset]).to eq(1)
      expect(metadata[:total_items]).to eq(5)
      expect(metadata[:returned_items]).to eq(2)
    end
  end
end
