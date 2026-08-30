# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::SearchModules do
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
    [
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
    ]
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:search_modules).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_search_modules')
    end
  end

  describe 'Input Schema Validation' do
    it 'defines query as required parameter' do
      input_schema = described_class.input_schema
      expect(input_schema.schema[:required]).to include("query")
    end

    it 'defines query as string type with length constraints' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:query][:type]).to eq('string')
      expect(properties[:query][:minLength]).to eq(1)
      expect(properties[:query][:maxLength]).to eq(500)
    end

    it 'defines limit as optional integer with constraints' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:limit][:type]).to eq('integer')
      expect(properties[:limit][:minimum]).to eq(1)
      expect(properties[:limit][:maximum]).to eq(1000)
      expect(properties[:limit][:default]).to eq(100)
    end

    it 'defines offset as optional integer' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:offset][:type]).to eq('integer')
      expect(properties[:offset][:minimum]).to eq(0)
      expect(properties[:offset][:default]).to eq(0)
    end
  end

  describe 'Output Schema' do
    it 'returns response with metadata and data keys' do
      output_schema = described_class.output_schema.schema
      expect(output_schema[:required]).to include('metadata', 'data')
      expect(output_schema[:properties][:metadata]).to be_a(Hash)
      expect(output_schema[:properties][:data]).to be_a(Hash)
    end

    it 'metadata includes query, query_time, total_items, and pagination' do
      properties = described_class.output_schema.schema[:properties][:metadata][:properties]
      expect(properties[:query]).to eq({ type: 'string' })
      expect(properties[:query_time]).to eq({ type: 'number' })
      expect(properties[:total_items]).to eq({ type: 'integer' })
      expect(properties[:returned_items]).to eq({ type: 'integer' })
      expect(properties[:limit]).to eq({ type: 'integer' })
      expect(properties[:offset]).to eq({ type: 'integer' })
    end

    it 'data array contains modules with required fields' do
      data_schema = described_class.output_schema.schema[:properties][:data]
      expect(data_schema[:type]).to eq('array')
      expect(data_schema[:items]).to be_a(Hash)
      expect(data_schema[:items][:properties]).to be_a(Hash)
    end

    it 'each module has fullname, type, and name as required fields' do
      item_properties = described_class.output_schema.schema[:properties][:data][:items][:properties]
      expect(item_properties[:fullname]).to eq({ type: 'string' })
      expect(item_properties[:type]).to eq({ type: 'string' })
      expect(item_properties[:name]).to eq({ type: 'string' })
      expect(item_properties[:rank]).to eq({ type: 'string' })
      expect(item_properties[:disclosure_date]).to eq({ type: 'string' })
    end

    it 'module type is one of the allowed enum values' do
      item_properties = described_class.output_schema.schema[:properties][:data][:items][:properties]
      expect(item_properties[:type][:type]).to eq('string')
    end
  end

  describe '.call' do
    it 'validates search query' do
      result = described_class.call(query: '', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/query/i)
    end

    it 'checks rate limit' do
      described_class.call(query: 'smb', server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('search_modules')
    end

    it 'calls Metasploit client with query' do
      described_class.call(query: 'smb windows', server_context: server_context)
      expect(msf_client).to have_received(:search_modules).with('smb windows')
    end

    it 'returns MCP::Tool::Response' do
      result = described_class.call(query: 'smb', server_context: server_context)
      expect(result).to be_a(MCP::Tool::Response)
    end

    it 'includes metadata in response' do
      result = described_class.call(query: 'smb', server_context: server_context)

      metadata = result.structured_content[:metadata]
      expect(metadata[:query]).to eq('smb')
      expect(metadata[:query_time]).to be_a(Float)
      expect(metadata[:total_items]).to eq(2)
      expect(metadata[:returned_items]).to eq(2)
      expect(metadata[:limit]).to eq(100)
      expect(metadata[:offset]).to eq(0)
    end

    it 'includes transformed data in response' do
      result = described_class.call(query: 'smb', server_context: server_context)

      data = result.structured_content[:data]
      expect(data).to be_an(Array)
      expect(data.length).to eq(2)
      expect(data.first[:fullname]).to eq('exploit/windows/smb/ms17_010_eternalblue')
    end

    it 'handles pagination with limit' do
      result = described_class.call(query: 'smb', limit: 1, server_context: server_context)

      metadata = result.structured_content[:metadata]
      expect(metadata[:limit]).to eq(1)
      expect(metadata[:returned_items]).to eq(1)
      expect(result.structured_content[:data].length).to eq(1)
    end

    it 'handles pagination with offset' do
      result = described_class.call(query: 'smb', offset: 1, server_context: server_context)

      metadata = result.structured_content[:metadata]
      expect(metadata[:offset]).to eq(1)
      expect(metadata[:returned_items]).to eq(1)
      expect(result.structured_content[:data].first[:fullname]).to eq('auxiliary/scanner/smb/smb_version')
    end

    it 'validates limit parameter' do
      result = described_class.call(query: 'smb', limit: 0, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/limit/i)
    end

    it 'validates offset parameter' do
      result = described_class.call(query: 'smb', offset: -1, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/offset/i)
    end

    it 'returns error response for authentication errors' do
      allow(msf_client).to receive(:search_modules).and_raise(
        Msf::MCP::Metasploit::AuthenticationError.new('Invalid token')
      )

      result = described_class.call(query: 'smb', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Authentication failed/)
    end

    it 'returns error response for API errors' do
      allow(msf_client).to receive(:search_modules).and_raise(
        Msf::MCP::Metasploit::APIError.new('Server error')
      )

      result = described_class.call(query: 'smb', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Metasploit API error/)
    end

    it 'returns error response for validation errors' do
      allow(rate_limiter).to receive(:check_rate_limit!).and_raise(
        Msf::MCP::Security::ValidationError.new('Rate limit exceeded')
      )

      result = described_class.call(query: 'smb', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Rate limit exceeded/)
    end

    it 'returns error response for rate limit exceeded' do
      allow(rate_limiter).to receive(:check_rate_limit!)
        .and_raise(Msf::MCP::Security::RateLimitExceededError.new(60))

      result = described_class.call(query: 'smb', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Rate limit exceeded/)
    end

    it 'handles empty search results' do
      allow(msf_client).to receive(:search_modules).and_return([])

      result = described_class.call(query: 'nonexistent', server_context: server_context)

      expect(result.structured_content[:metadata][:total_items]).to eq(0)
      expect(result.structured_content[:metadata][:returned_items]).to eq(0)
      expect(result.structured_content[:data]).to eq([])
    end

    it 'returns content array with text representation' do
      result = described_class.call(query: 'smb', server_context: server_context)

      expect(result.content).to be_an(Array)
      expect(result.content.first[:type]).to eq('text')
      expect(result.content.first[:text]).to be_a(String)

      parsed = JSON.parse(result.content.first[:text])
      expect(parsed['metadata']).to be_a(Hash)
      expect(parsed['data']).to be_an(Array)
    end
  end
end
