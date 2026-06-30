# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::ModuleExecute do
  let(:msf_client) { double('Msf::MCP::Metasploit::Client') }
  let(:rate_limiter) { double('Msf::MCP::Security::RateLimiter') }
  let(:server_context) do
    {
      msf_client: msf_client,
      rate_limiter: rate_limiter,
      config: {},
      dangerous_actions: true
    }
  end

  let(:msf_response) { { 'job_id' => 7, 'uuid' => 'abc123def456ghi789jkl012' } }

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:module_execute).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_module_execute')
    end
  end

  describe 'Input Schema' do
    it 'requires type, name and options' do
      expect(described_class.input_schema.schema[:required]).to match_array(%w[type name options])
    end

    it 'restricts type to the supported enum' do
      expect(described_class.input_schema.schema[:properties][:type][:enum])
        .to match_array(%w[exploit auxiliary post payload evasion])
    end
  end

  describe 'Annotations' do
    it 'is marked as a destructive, non-idempotent tool' do
      annotations = described_class.annotations_value
      expect(annotations.destructive_hint).to eq(true)
      expect(annotations.read_only_hint).to eq(false)
      expect(annotations.idempotent_hint).to eq(false)
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('module_execute')
    end

    it 'forwards type, name, and options unchanged to msf_client.module_execute (does not bypass AutoCheck)' do
      options = { 'RHOSTS' => '192.0.2.10', 'PAYLOAD' => 'windows/meterpreter/reverse_tcp' }
      described_class.call(type: 'exploit', name: 'multi/handler', options: options, server_context: server_context)
      expect(msf_client).to have_received(:module_execute).with('exploit', 'multi/handler', options)
    end

    it 'stringifies Symbol option keys before forwarding (MCP deep-symbolizes JSON input)' do
      described_class.call(
        type: 'exploit',
        name: 'multi/handler',
        options: { RHOSTS: '192.0.2.10', PAYLOAD: 'windows/meterpreter/reverse_tcp' },
        server_context: server_context
      )
      expect(msf_client).to have_received(:module_execute).with(
        'exploit',
        'multi/handler',
        { 'RHOSTS' => '192.0.2.10', 'PAYLOAD' => 'windows/meterpreter/reverse_tcp' }
      )
    end

    it 'returns a structured response with job_id and uuid' do
      result = described_class.call(type: 'auxiliary', name: 'scanner/smb/smb_version', options: {}, server_context: server_context)

      expect(result).to be_a(MCP::Tool::Response)
      expect(result.structured_content[:data][:job_id]).to eq(7)
      expect(result.structured_content[:data][:uuid]).to eq('abc123def456ghi789jkl012')
      expect(result.structured_content[:metadata][:query_time]).to be_a(Float)
    end

    it 'rejects invalid module types' do
      result = described_class.call(type: 'invalid_type', name: 'foo', options: {}, server_context: server_context)
      expect(result.error?).to be true
    end

    it 'rejects invalid module names' do
      result = described_class.call(type: 'exploit', name: 'invalid name!', options: {}, server_context: server_context)
      expect(result.error?).to be true
    end

    it 'rejects non-Hash options' do
      result = described_class.call(type: 'exploit', name: 'multi/handler', options: 'string', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Module options/)
    end

    it 'returns API error response' do
      allow(msf_client).to receive(:module_execute).and_raise(Msf::MCP::Metasploit::APIError.new('Module not found'))
      result = described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Metasploit API error/)
    end

    it 'returns rate limit error response' do
      allow(rate_limiter).to receive(:check_rate_limit!)
        .and_raise(Msf::MCP::Security::RateLimitExceededError.new(60))
      result = described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Rate limit exceeded/)
    end
  end

  describe '.call with dangerous mode disabled' do
    let(:disabled_context) do
      {
        msf_client: msf_client,
        rate_limiter: rate_limiter,
        config: {},
        dangerous_actions: false
      }
    end

    it 'returns an error response when dangerous_actions is false' do
      result = described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: disabled_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/dangerous actions mode/i)
      expect(result.content.first[:text]).to include('--enable-dangerous-actions')
    end

    it 'returns an error response when dangerous_actions key is missing' do
      result = described_class.call(
        type: 'exploit', name: 'multi/handler', options: {},
        server_context: { msf_client: msf_client, rate_limiter: rate_limiter, config: {} }
      )
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/dangerous actions mode/i)
    end

    it 'does not call msf_client.module_execute when blocked' do
      described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: disabled_context)
      expect(msf_client).not_to have_received(:module_execute)
    end

    it 'does not consume rate limit when blocked' do
      described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: disabled_context)
      expect(rate_limiter).not_to have_received(:check_rate_limit!)
    end
  end
end
