# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::HostInfo do
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
      'hosts' => [
        {
          'address' => '192.168.1.100',
          'mac' => '00:11:22:33:44:55',
          'name' => 'testhost',
          'os_name' => 'Linux',
          'os_flavor' => 'Ubuntu',
          'state' => 'alive',
          'created_at' => 1609459200,
          'updated_at' => 1640995200
        },
        {
          'address' => '192.168.1.101',
          'mac' => '00:11:22:33:44:56',
          'name' => 'testhost2',
          'os_name' => 'Windows',
          'state' => 'alive',
          'created_at' => 1609459300
        }
      ]
    }
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:db_hosts).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_host_info')
    end
  end

  describe 'Input Schema Validation' do
    it 'defines workspace as optional parameter with default' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:workspace][:type]).to eq('string')
      expect(properties[:workspace][:default]).to eq('default')
    end

    it 'defines addresses as optional string parameter' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:addresses][:type]).to eq('string')
    end

    it 'defines only_up as optional boolean parameter' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:only_up][:type]).to eq('boolean')
    end

    it 'supports pagination with limit and offset' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:limit]).not_to be_nil
      expect(properties[:offset]).not_to be_nil
    end
  end

  describe 'Output Schema' do
    it 'returns hosts with IP, OS, MAC, timestamps' do
      data_items = described_class.output_schema.schema[:properties][:data][:items][:properties]

      expect(data_items[:address]).to eq({ type: 'string' })
      expect(data_items[:mac_address]).to eq({ type: 'string' })
      expect(data_items[:hostname]).to eq({ type: 'string' })
      expect(data_items[:os_name]).to eq({ type: 'string' })
      expect(data_items[:os_flavor]).to eq({ type: 'string' })
      expect(data_items[:created_at]).to eq({ type: 'string' })
      expect(data_items[:updated_at]).to eq({ type: 'string' })
    end

    it 'includes workspace in metadata' do
      metadata_properties = described_class.output_schema.schema[:properties][:metadata][:properties]
      expect(metadata_properties[:workspace]).to eq({ type: 'string' })
      expect(metadata_properties[:query_time]).to eq({ type: 'number' })
      expect(metadata_properties[:total_items]).to eq({ type: 'integer' })
      expect(metadata_properties[:returned_items]).to eq({ type: 'integer' })
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('host_info')
    end

    it 'calls Metasploit client with workspace' do
      described_class.call(workspace: 'test_ws', server_context: server_context)
      expect(msf_client).to have_received(:db_hosts).with(hash_including(workspace: 'test_ws'))
    end

    it 'uses default workspace' do
      described_class.call(server_context: server_context)
      expect(msf_client).to have_received(:db_hosts).with(hash_including(workspace: 'default'))
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
      expect(data.first[:address]).to eq('192.168.1.100')
      expect(data.first[:hostname]).to eq('testhost')
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
      expect(result.structured_content[:data].first[:address]).to eq('192.168.1.101')
    end

    it 'passes addresses filter to MSF client' do
      described_class.call(addresses: '192.168.1.0/24', server_context: server_context)
      expect(msf_client).to have_received(:db_hosts).with(hash_including(addresses: '192.168.1.0/24'))
    end

    it 'passes only_up filter to MSF client' do
      described_class.call(only_up: true, server_context: server_context)
      expect(msf_client).to have_received(:db_hosts).with(hash_including(only_up: true))
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

    it 'returns error response for authentication errors' do
      allow(msf_client).to receive(:db_hosts).and_raise(
        Msf::MCP::Metasploit::AuthenticationError.new('Invalid token')
      )

      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Authentication failed/)
    end

    it 'returns error response for API errors' do
      allow(msf_client).to receive(:db_hosts).and_raise(
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

    it 'handles empty results' do
      allow(msf_client).to receive(:db_hosts).and_return({ 'hosts' => [] })

      result = described_class.call(server_context: server_context)

      expect(result.structured_content[:metadata][:total_items]).to eq(0)
      expect(result.structured_content[:metadata][:returned_items]).to eq(0)
      expect(result.structured_content[:data]).to eq([])
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
