# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::RunningStats do
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
      'waiting' => ['uuid_w_1'],
      'running' => ['uuid_r_1', 'uuid_r_2'],
      'results' => ['uuid_d_1']
    }
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:running_stats).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_running_stats')
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
      described_class.call(server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('running_stats')
    end

    it 'returns the running stats arrays as structured content' do
      result = described_class.call(server_context: server_context)
      expect(result.structured_content[:data][:waiting]).to eq(['uuid_w_1'])
      expect(result.structured_content[:data][:running]).to eq(['uuid_r_1', 'uuid_r_2'])
      expect(result.structured_content[:data][:results]).to eq(['uuid_d_1'])
    end

    it 'tolerates missing keys in the upstream response' do
      allow(msf_client).to receive(:running_stats).and_return({})
      result = described_class.call(server_context: server_context)
      expect(result.structured_content[:data][:waiting]).to eq([])
      expect(result.structured_content[:data][:running]).to eq([])
      expect(result.structured_content[:data][:results]).to eq([])
    end

    it 'returns an error response for API errors' do
      allow(msf_client).to receive(:running_stats).and_raise(Msf::MCP::Metasploit::APIError.new('boom'))
      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Metasploit API error/)
    end
  end
end
