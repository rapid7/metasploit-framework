# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::ModuleResults do
  let(:msf_client) { double('Msf::MCP::Metasploit::Client') }
  let(:rate_limiter) { double('Msf::MCP::Security::RateLimiter') }
  let(:server_context) do
    {
      msf_client: msf_client,
      rate_limiter: rate_limiter,
      config: {}
    }
  end

  let(:valid_uuid) { 'abc12345def67890ghi12345' }

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:module_results).and_return({ 'status' => 'completed', 'result' => 'ok' })
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_module_results')
    end
  end

  describe 'Annotations' do
    it 'is marked as read-only and idempotent' do
      annotations = described_class.annotations_value
      expect(annotations.read_only_hint).to eq(true)
      expect(annotations.idempotent_hint).to eq(true)
      expect(annotations.destructive_hint).to eq(false)
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(uuid: valid_uuid, server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('module_results')
    end

    it 'forwards UUID to msf_client.module_results' do
      described_class.call(uuid: valid_uuid, server_context: server_context)
      expect(msf_client).to have_received(:module_results).with(valid_uuid)
    end

    it 'returns the status and result as structured content' do
      result = described_class.call(uuid: valid_uuid, server_context: server_context)
      expect(result.structured_content[:data][:status]).to eq('completed')
      expect(result.structured_content[:data][:result]).to eq('ok')
    end

    it 'rejects invalid UUID format' do
      result = described_class.call(uuid: 'BAD-UUID!', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/UUID/)
    end

    it 'rejects non-string UUID' do
      result = described_class.call(uuid: 123, server_context: server_context)
      expect(result.error?).to be true
    end

    it 'returns an error response for API errors' do
      allow(msf_client).to receive(:module_results).and_raise(Msf::MCP::Metasploit::APIError.new('Not found'))
      result = described_class.call(uuid: valid_uuid, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Metasploit API error/)
    end
  end
end
