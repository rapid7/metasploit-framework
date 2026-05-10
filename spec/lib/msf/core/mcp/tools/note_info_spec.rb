# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::NoteInfo do
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
      'notes' => [
        {
          'id' => 1,
          'host' => '192.168.1.100',
          'service' => 'https',
          'port' => 443,
          'protocol' => 'tcp',
          'ntype' => 'ssl.certificate',
          'data' => {
            'cn' => 'example.com',
            'issuer' => 'Let\'s Encrypt',
            'expiration' => '2024-12-31'
          },
          'critical' => false,
          'seen' => false,
          'created_at' => 1609459200,
          'updated_at' => 1640995200
        },
        {
          'id' => 2,
          'host' => '192.168.1.101',
          'service' => 'smb',
          'port' => 445,
          'protocol' => 'tcp',
          'ntype' => 'smb.fingerprint',
          'data' => {
            'os' => 'Windows Server 2019',
            'version' => '10.0'
          },
          'critical' => false,
          'seen' => true,
          'created_at' => 1609459300
        }
      ]
    }
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:db_notes).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_note_info')
    end
  end

  describe 'Input Schema Validation' do
    it 'defines workspace as required parameter' do
      input_schema = described_class.input_schema
      expect(input_schema.schema[:required]).to include('workspace')
    end
  end

  describe 'Output Schema' do
    it 'returns notes with type, content, timestamps' do
      data_items = described_class.output_schema.schema[:properties][:data][:items][:properties]

      expect(data_items[:host]).to eq({ type: 'string' })
      expect(data_items[:service_name_or_port]).to eq({ type: 'string' })
      expect(data_items[:note_type]).to eq({ type: 'string' })
      expect(data_items[:data]).to eq({ type: 'string' })
      expect(data_items[:created_at]).to eq({ type: 'string' })
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('note_info')
    end

    it 'calls Metasploit client with workspace' do
      described_class.call(workspace: 'test_ws', server_context: server_context)
      expect(msf_client).to have_received(:db_notes).with(hash_including(workspace: 'test_ws'))
    end

    it 'uses default workspace' do
      described_class.call(server_context: server_context)
      expect(msf_client).to have_received(:db_notes).with(hash_including(workspace: 'default'))
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
      expect(data.first[:host]).to eq('192.168.1.100')
      expect(data.first[:note_type]).to eq('ssl.certificate')
      expect(data.first[:service_name_or_port]).to eq('https')
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
      expect(result.structured_content[:data].length).to eq(1)
    end

    it 'handles filtering by type' do
      described_class.call(type: 'ssl.certificate', server_context: server_context)

      expect(msf_client).to have_received(:db_notes).with(
        hash_including(ntype: 'ssl.certificate')
      )
    end

    it 'handles filtering by host' do
      described_class.call(host: '192.168.1.100', server_context: server_context)

      expect(msf_client).to have_received(:db_notes).with(
        hash_including(address: '192.168.1.100')
      )
    end

    it 'handles filtering by ports' do
      described_class.call(ports: '443', server_context: server_context)

      expect(msf_client).to have_received(:db_notes).with(
        hash_including(ports: '443')
      )
    end

    it 'handles filtering by protocol' do
      described_class.call(protocol: 'tcp', server_context: server_context)

      expect(msf_client).to have_received(:db_notes).with(
        hash_including(proto: 'tcp')
      )
    end

    it 'handles empty results' do
      allow(msf_client).to receive(:db_notes).and_return({ 'notes' => [] })

      result = described_class.call(server_context: server_context)

      expect(result.structured_content[:data]).to eq([])
      expect(result.structured_content[:metadata][:total_items]).to eq(0)
      expect(result.structured_content[:metadata][:returned_items]).to eq(0)
    end

    it 'returns error response for rate limit exceeded' do
      allow(rate_limiter).to receive(:check_rate_limit!)
        .and_raise(Msf::MCP::Security::RateLimitExceededError.new(60))

      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Rate limit exceeded/)
    end

    it 'returns error response for API errors' do
      allow(msf_client).to receive(:db_notes)
        .and_raise(Msf::MCP::Metasploit::APIError, 'Database error')

      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Metasploit API error/)
    end

    it 'returns error response for authentication errors' do
      allow(msf_client).to receive(:db_notes).and_raise(
        Msf::MCP::Metasploit::AuthenticationError.new('Invalid token')
      )

      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Authentication failed/)
    end

    it 'passes pagination parameters to MSF client' do
      # Pagination is applied client-side, not in the API call
      described_class.call(limit: 50, offset: 10, server_context: server_context)

      # API call only receives workspace parameter
      expect(msf_client).to have_received(:db_notes).with(
        hash_including(workspace: 'default')
      )
    end
  end
end
