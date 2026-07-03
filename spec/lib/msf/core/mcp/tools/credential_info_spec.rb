# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::CredentialInfo do
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
      'creds' => [
        {
          'user' => 'admin',
          'pass' => 'password123',
          'type' => 'password',
          'host' => '192.168.1.100',
          'sname' => 'smb',
          'port' => 445,
          'proto' => 'tcp',
          'updated_at' => 1640995200
        },
        {
          'user' => 'root',
          'pass' => 'toor',
          'type' => 'password',
          'host' => '192.168.1.101',
          'sname' => 'ssh',
          'port' => 22,
          'proto' => 'tcp',
          'updated_at' => 1609459300
        }
      ]
    }
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:db_creds).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name from contract' do
      expect(described_class.tool_name).to eq('msf_credential_info')
    end
  end

  describe 'Input Schema Validation' do
    it 'defines workspace as required parameter' do
      input_schema = described_class.input_schema
      expect(input_schema.schema[:required]).to include('workspace')
    end

    it 'supports pagination parameters' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:limit]).not_to be_nil
      expect(properties[:offset]).not_to be_nil
    end
  end

  describe 'Response Structure' do
    it 'returns credentials with username, type, source' do
      # Validate output_schema defines credential fields
      data_items = described_class.output_schema.schema[:properties][:data][:items][:properties]

      expect(data_items[:host]).to eq({ type: 'string' })
      expect(data_items[:port]).to eq({ type: 'integer' })
      expect(data_items[:protocol]).to eq({ type: 'string' })
      expect(data_items[:service_name]).to eq({ type: 'string' })
      expect(data_items[:user]).to eq({ type: 'string' })
      expect(data_items[:type]).to eq({ type: 'string' })
      expect(data_items[:updated_at]).to eq({ type: 'string' })
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('credential_info')
    end

    it 'calls Metasploit client with workspace' do
      described_class.call(workspace: 'test_ws', server_context: server_context)
      expect(msf_client).to have_received(:db_creds).with(hash_including(workspace: 'test_ws'))
    end

    it 'uses default workspace' do
      described_class.call(server_context: server_context)
      expect(msf_client).to have_received(:db_creds).with(hash_including(workspace: 'default'))
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
      expect(data.first[:user]).to eq('admin')
      expect(data.first[:type]).to eq('password')
      expect(data.first[:port]).to eq(445)
      expect(data.first[:protocol]).to eq('tcp')
      expect(data.first[:service_name]).to eq('smb')
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

    it 'handles empty results' do
      allow(msf_client).to receive(:db_creds).and_return({ 'creds' => [] })

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
      allow(msf_client).to receive(:db_creds)
        .and_raise(Msf::MCP::Metasploit::APIError, 'Database error')

      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Metasploit API error/)
    end

    it 'returns error response for authentication errors' do
      allow(msf_client).to receive(:db_creds).and_raise(
        Msf::MCP::Metasploit::AuthenticationError.new('Invalid token')
      )

      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Authentication failed/)
    end
  end
end
