# frozen_string_literal: true

require 'msf/core/mcp'
require 'webmock/rspec'

RSpec.describe 'Tool Execution End-to-End - Search Modules' do
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

  describe 'Module Search Integration with HTTP' do
    it 'executes module search through complete HTTP request flow' do
      # Stub authentication endpoint
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub module search endpoint with realistic response
      # Note: The MessagePackClient returns the unpacked response directly,
      # so we need to return an array, not a hash with 'modules' key
      search_stub = stub_request(:post, api_url)
        .with(body: ['module.search', 'test_token', 'smb'].to_msgpack)
        .to_return(
          status: 200,
          body: [
            {
              'name' => 'ms17_010_eternalblue',
              'fullname' => 'exploit/windows/smb/ms17_010_eternalblue',
              'type' => 'exploit',
              'rank' => 'excellent',
              'disclosuredate' => '2017-03-14',
              'description' => 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption'
            },
            {
              'name' => 'smb_version',
              'fullname' => 'auxiliary/scanner/smb/smb_version',
              'type' => 'auxiliary',
              'rank' => 'normal',
              'description' => 'SMB Version Detection'
            }
          ].to_msgpack,
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

      # Execute search through complete stack
      result = Msf::MCP::Tools::SearchModules.call(
        query: 'smb',
        server_context: server_context
      )

      # Verify HTTP request was made
      expect(search_stub).to have_been_requested.once

      # Verify MCP response structure
      expect(result).to be_a(MCP::Tool::Response)
      expect(result.content).to be_an(Array)
      expect(result.content.first[:type]).to eq('text')

      # Verify data transformation occurred correctly
      data = result.structured_content[:data]
      expect(data).to be_an(Array)
      expect(data.length).to eq(2)
      expect(data.first[:fullname]).to eq('exploit/windows/smb/ms17_010_eternalblue')
      expect(data.first[:type]).to eq('exploit')

      # Verify metadata
      metadata = result.structured_content[:metadata]
      expect(metadata[:query]).to eq('smb')
      expect(metadata[:total_items]).to eq(2)
      expect(metadata[:returned_items]).to eq(2)
    end

    it 'handles empty search results through complete HTTP flow' do
      # Stub authentication
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub search with empty results
      search_stub = stub_request(:post, api_url)
        .with(body: ['module.search', 'test_token', 'nonexistent_module_xyz'].to_msgpack)
        .to_return(
          status: 200,
          body: [].to_msgpack,
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

      # Execute search
      result = Msf::MCP::Tools::SearchModules.call(
        query: 'nonexistent_module_xyz',
        server_context: server_context
      )

      # Verify HTTP request was made
      expect(search_stub).to have_been_requested.once

      # Verify empty results handled correctly
      expect(result).to be_a(MCP::Tool::Response)
      expect(result.structured_content[:data]).to eq([])
      expect(result.structured_content[:metadata][:total_items]).to eq(0)
      expect(result.structured_content[:metadata][:returned_items]).to eq(0)
    end

    it 'applies pagination correctly through HTTP request' do
      # Stub authentication
      stub_request(:post, api_url)
        .with(body: ['auth.login', user, password].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      # Stub search with multiple results
      search_stub = stub_request(:post, api_url)
        .with(body: ['module.search', 'test_token', 'scanner'].to_msgpack)
        .to_return(
          status: 200,
          body: [
            { 'fullname' => 'auxiliary/scanner/http/http_version', 'type' => 'auxiliary', 'name' => 'http_version' },
            { 'fullname' => 'auxiliary/scanner/smb/smb_version', 'type' => 'auxiliary', 'name' => 'smb_version' },
            { 'fullname' => 'auxiliary/scanner/ssh/ssh_version', 'type' => 'auxiliary', 'name' => 'ssh_version' },
            { 'fullname' => 'auxiliary/scanner/ftp/ftp_version', 'type' => 'auxiliary', 'name' => 'ftp_version' }
          ].to_msgpack,
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

      # Execute search with pagination
      result = Msf::MCP::Tools::SearchModules.call(
        query: 'scanner',
        limit: 2,
        offset: 1,
        server_context: server_context
      )

      # Verify HTTP request was made
      expect(search_stub).to have_been_requested.once

      # Verify pagination applied correctly (offset=1, limit=2 means items 2 and 3)
      expect(result).to be_a(MCP::Tool::Response)
      data = result.structured_content[:data]
      expect(data.length).to eq(2)
      expect(data.first[:fullname]).to eq('auxiliary/scanner/smb/smb_version')
      expect(data.last[:fullname]).to eq('auxiliary/scanner/ssh/ssh_version')

      # Verify pagination metadata
      metadata = result.structured_content[:metadata]
      expect(metadata[:limit]).to eq(2)
      expect(metadata[:offset]).to eq(1)
      expect(metadata[:total_items]).to eq(4)
      expect(metadata[:returned_items]).to eq(2)
    end
  end
end
