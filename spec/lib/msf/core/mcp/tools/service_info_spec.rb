# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::ServiceInfo do
  let(:msf_client) { double('Msf::MCP::Metasploit::Client') }
  let(:rate_limiter) { double('Msf::MCP::Security::RateLimiter') }
  let(:server_context) do
    {
      msf_client: msf_client,
      rate_limiter: rate_limiter,
      config: {}
    }
  end

  let(:msf_response) do
    {
      'services' => [
        {
          'host' => '192.168.1.100',
          'port' => 80,
          'proto' => 'tcp',
          'state' => 'open',
          'name' => 'http',
          'info' => 'Apache httpd 2.4.41',
          'created_at' => 1609459200,
          'updated_at' => 1640995200
        },
        {
          'host' => '192.168.1.100',
          'port' => 443,
          'proto' => 'tcp',
          'state' => 'open',
          'name' => 'https',
          'info' => 'Apache httpd 2.4.41 (SSL)',
          'created_at' => 1609459300,
          'updated_at' => 1640995300
        }
      ]
    }
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:db_services).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_service_info')
    end
  end

  describe 'Input Schema Validation' do
    it 'defines workspace as required parameter' do
      input_schema = described_class.input_schema
      expect(input_schema.schema[:required]).to include('workspace')
    end

    it 'supports multiple filter parameters' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:host]).not_to be_nil
      expect(properties[:ports]).not_to be_nil
      expect(properties[:protocol]).not_to be_nil
      expect(properties[:names]).not_to be_nil
      expect(properties[:only_up]).not_to be_nil
    end
  end

  describe 'Output Schema' do
    it 'returns services with port, protocol, service_name' do
      data_items = described_class.output_schema.schema[:properties][:data][:items][:properties]

      expect(data_items[:port]).to eq({ type: 'integer' })
      expect(data_items[:protocol]).to eq({ type: 'string' })
      expect(data_items[:name]).to eq({ type: 'string' })
      expect(data_items[:host_address]).to eq({ type: 'string' })
      expect(data_items[:state]).to eq({ type: 'string' })
      expect(data_items[:info]).to eq({ type: 'string' })
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('service_info')
    end

    it 'calls Metasploit client with workspace' do
      described_class.call(workspace: 'test_ws', server_context: server_context)
      expect(msf_client).to have_received(:db_services).with(hash_including(workspace: 'test_ws'))
    end

    it 'uses default workspace' do
      described_class.call(server_context: server_context)
      expect(msf_client).to have_received(:db_services).with(hash_including(workspace: 'default'))
    end

    it 'returns MCP::Tool::Response' do
      result = described_class.call(server_context: server_context)
      expect(result).to be_a(MCP::Tool::Response)
    end

    it 'includes metadata in response' do
      result = described_class.call(workspace: 'default', server_context: server_context)

      metadata = result.structured_content[:metadata]
      expect(metadata[:workspace]).to eq('default')
      expect(metadata[:query_time]).to be_a(Float)
      expect(metadata[:total_items]).to eq(2)
      expect(metadata[:returned_items]).to eq(2)
      expect(metadata[:limit]).to eq(100)
      expect(metadata[:offset]).to eq(0)
    end

    it 'includes transformed data in response' do
      result = described_class.call(server_context: server_context)

      data = result.structured_content[:data]
      expect(data).to be_an(Array)
      expect(data.length).to eq(2)
      expect(data.first[:host_address]).to eq('192.168.1.100')
      expect(data.first[:port]).to eq(80)
      expect(data.first[:protocol]).to eq('tcp')
      expect(data.first[:name]).to eq('http')
      expect(data.first[:state]).to eq('open')
    end

    it 'handles pagination with limit' do
      result = described_class.call(limit: 1, server_context: server_context)

      metadata = result.structured_content[:metadata]
      expect(metadata[:limit]).to eq(1)
      expect(metadata[:returned_items]).to eq(1)
      expect(result.structured_content[:data].length).to eq(1)
    end

    it 'handles pagination with offset' do
      result = described_class.call(offset: 1, server_context: server_context)

      metadata = result.structured_content[:metadata]
      expect(metadata[:offset]).to eq(1)
      expect(metadata[:returned_items]).to eq(1)
      expect(result.structured_content[:data].first[:port]).to eq(443)
    end

    it 'passes host filter to MSF client' do
      described_class.call(host: '192.168.1.100', server_context: server_context)
      expect(msf_client).to have_received(:db_services).with(hash_including(addresses: '192.168.1.100'))
    end

    it 'passes ports filter to MSF client' do
      described_class.call(ports: '80', server_context: server_context)
      expect(msf_client).to have_received(:db_services).with(hash_including(ports: '80'))
    end

    it 'passes protocol filter to MSF client' do
      described_class.call(protocol: 'tcp', server_context: server_context)
      expect(msf_client).to have_received(:db_services).with(hash_including(proto: 'tcp'))
    end

    it 'passes names filter to MSF client' do
      described_class.call(names: 'http,https', server_context: server_context)
      expect(msf_client).to have_received(:db_services).with(hash_including(names: 'http,https'))
    end

    it 'passes only_up filter to MSF client' do
      described_class.call(only_up: true, server_context: server_context)
      expect(msf_client).to have_received(:db_services).with(hash_including(only_up: true))
    end

    it 'validates limit parameter' do
      result = described_class.call(limit: 0, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/limit/i)
    end

    it 'validates offset parameter' do
      result = described_class.call(offset: -1, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/offset/i)
    end

    it 'validates protocol parameter' do
      result = described_class.call(protocol: 'invalid', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/protocol/i)
    end

    it 'handles empty results' do
      allow(msf_client).to receive(:db_services).and_return({ 'services' => [] })

      result = described_class.call(server_context: server_context)

      expect(result.structured_content[:data]).to eq([])
      expect(result.structured_content[:metadata][:total_items]).to eq(0)
      expect(result.structured_content[:metadata][:returned_items]).to eq(0)
    end

    it 'returns error response for authentication errors' do
      allow(msf_client).to receive(:db_services).and_raise(
        Msf::MCP::Metasploit::AuthenticationError.new('Invalid token')
      )

      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Authentication failed/)
    end

    it 'returns error response for API errors' do
      allow(msf_client).to receive(:db_services).and_raise(
        Msf::MCP::Metasploit::APIError.new('Server error')
      )

      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Metasploit API error/)
    end

    it 'returns error response for rate limit exceeded' do
      allow(rate_limiter).to receive(:check_rate_limit!)
        .and_raise(Msf::MCP::Security::RateLimitExceededError.new(60))

      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Rate limit exceeded/)
    end

    it 'returns content array with text representation' do
      result = described_class.call(server_context: server_context)

      expect(result.content).to be_an(Array)
      expect(result.content.first[:type]).to eq('text')
      expect(result.content.first[:text]).to be_a(String)

      parsed = JSON.parse(result.content.first[:text])
      expect(parsed['metadata']).to be_a(Hash)
      expect(parsed['data']).to be_an(Array)
    end
  end
end
