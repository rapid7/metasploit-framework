# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::SessionList do
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
      1 => {
        'type' => 'meterpreter',
        'tunnel_local' => '192.0.2.10:4444',
        'tunnel_peer' => '192.0.2.20:52341',
        'via_exploit' => 'exploit/windows/smb/ms17_010_eternalblue',
        'platform' => 'windows'
      },
      2 => {
        'type' => 'shell',
        'tunnel_local' => '192.0.2.10:4445',
        'tunnel_peer' => '192.0.2.30:33333'
      }
    }
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:session_list).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_session_list')
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
      expect(rate_limiter).to have_received(:check_rate_limit!).with('session_list')
    end

    it 'returns the upstream session hash as structured content' do
      result = described_class.call(server_context: server_context)
      expect(result.structured_content[:data]).to eq(msf_response)
    end

    it 'reports total_sessions in metadata' do
      result = described_class.call(server_context: server_context)
      expect(result.structured_content[:metadata][:total_sessions]).to eq(2)
    end

    it 'tolerates an empty session list' do
      allow(msf_client).to receive(:session_list).and_return({})
      result = described_class.call(server_context: server_context)
      expect(result.structured_content[:data]).to eq({})
      expect(result.structured_content[:metadata][:total_sessions]).to eq(0)
    end

    it 'returns an error response for API errors' do
      allow(msf_client).to receive(:session_list).and_raise(Msf::MCP::Metasploit::APIError.new('boom'))
      result = described_class.call(server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Metasploit API error/)
    end

    context 'dangerous_actions gate' do
      it 'returns a successful response even when dangerous_actions is false' do
        ctx = { msf_client: msf_client, rate_limiter: rate_limiter, config: {}, dangerous_actions: false }
        result = described_class.call(server_context: ctx)
        expect(result.error?).to be false
        expect(result.structured_content[:data]).to eq(msf_response)
      end
    end
  end
end
