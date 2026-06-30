# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::ModuleCheck do
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

  let(:msf_response) { { 'job_id' => 4, 'uuid' => 'aaaa1111bbbb2222cccc3333' } }

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:module_check).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_module_check')
    end
  end

  describe 'Input Schema' do
    it 'requires type, name, and options' do
      expect(described_class.input_schema.schema[:required]).to match_array(%w[type name options])
    end

    it 'restricts type to exploit and auxiliary' do
      expect(described_class.input_schema.schema[:properties][:type][:enum]).to match_array(%w[exploit auxiliary])
    end
  end

  describe 'Annotations' do
    it 'is marked as destructive' do
      annotations = described_class.annotations_value
      expect(annotations.destructive_hint).to eq(true)
      expect(annotations.read_only_hint).to eq(false)
      expect(annotations.idempotent_hint).to eq(false)
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('module_check')
    end

    it 'forwards type, name, options to msf_client.module_check' do
      options = { 'RHOSTS' => '192.0.2.10' }
      described_class.call(type: 'exploit', name: 'multi/handler', options: options, server_context: server_context)
      expect(msf_client).to have_received(:module_check).with('exploit', 'multi/handler', options)
    end

    it 'stringifies Symbol option keys before forwarding (MCP deep-symbolizes JSON input)' do
      described_class.call(
        type: 'exploit',
        name: 'multi/handler',
        options: { RHOSTS: '192.0.2.10', RPORT: 445 },
        server_context: server_context
      )
      expect(msf_client).to have_received(:module_check).with(
        'exploit',
        'multi/handler',
        { 'RHOSTS' => '192.0.2.10', 'RPORT' => 445 }
      )
    end

    it 'returns a structured response with job_id and uuid' do
      result = described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: server_context)
      expect(result.structured_content[:data][:job_id]).to eq(4)
      expect(result.structured_content[:data][:uuid]).to eq('aaaa1111bbbb2222cccc3333')
    end

    it 'rejects non-exploit/auxiliary types' do
      result = described_class.call(type: 'post', name: 'foo/bar', options: {}, server_context: server_context)
      expect(result.error?).to be true
    end

    it 'returns an unsupported structured response when the framework reports no check method' do
      allow(msf_client).to receive(:module_check).and_raise(
        Msf::MCP::Metasploit::APIError.new(Msf::Exploit::CheckCode::Unsupported.message)
      )

      result = described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: server_context)
      expect(result.error?).to be false
      expect(result.structured_content[:data][:status]).to eq('unsupported')
      expect(result.structured_content[:data][:message]).to match(/does not implement a check method/i)
    end

    it 'returns a normal API error response when the framework reports a different failure' do
      allow(msf_client).to receive(:module_check).and_raise(Msf::MCP::Metasploit::APIError.new('Module not found'))
      result = described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Module not found/)
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

    it 'does not call msf_client.module_check when blocked' do
      described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: disabled_context)
      expect(msf_client).not_to have_received(:module_check)
    end

    it 'does not consume rate limit when blocked' do
      described_class.call(type: 'exploit', name: 'multi/handler', options: {}, server_context: disabled_context)
      expect(rate_limiter).not_to have_received(:check_rate_limit!)
    end
  end
end
